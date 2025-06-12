package gourdiansession

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiansession/errs"
	"github.com/redis/go-redis/v9"
)

const (
	SessionStatusActive  string = "active"
	SessionStatusExpired string = "expired"
	SessionStatusRevoked string = "revoked"
)

// Role represents a role with its permissions in the session
type Role struct {
	Name        string       `json:"name" bson:"name"`
	Permissions []Permission `json:"permissions" bson:"permissions"`
}

// Permission represents a simplified permission in the session
type Permission struct {
	Name     string `json:"name" bson:"name"`
	Resource string `json:"resource" bson:"resource"`
	Action   string `json:"action" bson:"action"`
}

// GourdianSessionType holds session information
type GourdianSessionType struct {
	ID            int64           `json:"id" bson:"id" gorm:"type:bigint;autoIncrement;uniqueIndex"`
	UUID          uuid.UUID       `json:"uuid" bson:"uuid" gorm:"type:uuid;not null;uniqueIndex"`
	UserID        uuid.UUID       `gorm:"type:uuid;not null;index:user_id;index:user_status"`
	Authenticated bool            `json:"authenticated" bson:"authenticated"`
	Username      string          `json:"username" bson:"username"`
	Status        string          `json:"status" bson:"status" gorm:"type:varchar(16);index;index:user_status;index:status_expires"`
	IPAddress     *string         `json:"ip_address" bson:"ip_address"`
	UserAgent     *string         `json:"user_agent" bson:"user_agent"`
	Roles         []Role          `json:"roles" bson:"roles" gorm:"type:jsonb"`
	ExpiresAt     time.Time       `json:"expires_at" bson:"expires_at" gorm:"index:status_expires"`
	CreatedAt     time.Time       `json:"created_at" bson:"created_at"`
	LastActivity  time.Time       `json:"last_activity" bson:"last_activity"`
	DeletedAt     *time.Time      `json:"deleted_at" bson:"deleted_at" gorm:"index"`
	TempData      *map[string]any `json:"temp_data,omitempty" bson:"temp_data,omitempty" gorm:"-"` // runtime-only
}

// NewGurdianSessionObject initializes a new session object with defaults.
func NewGurdianSessionObject(
	userID uuid.UUID,
	username string,
	ipAddress, userAgent *string,
	roles []Role,
	sessionDuration time.Duration,
) *GourdianSessionType {
	now := time.Now()

	return &GourdianSessionType{
		UUID:          uuid.New(),
		UserID:        userID,
		Authenticated: true,
		Username:      username,
		Status:        SessionStatusActive,
		IPAddress:     ipAddress,
		UserAgent:     userAgent,
		Roles:         roles,
		ExpiresAt:     now.Add(sessionDuration),
		CreatedAt:     now,
		LastActivity:  now,
		TempData:      &map[string]any{},
	}
}

type GurdianSessionRepositoryInt interface {
	CreateSession(ctx context.Context, session *GourdianSessionType) (*GourdianSessionType, error)

	RevokeSessionByID(ctx context.Context, sessionID uuid.UUID) error

	GetSessionByID(ctx context.Context, sessionID uuid.UUID) (*GourdianSessionType, error)

	UpdateSession(ctx context.Context, session *GourdianSessionType) (*GourdianSessionType, error)

	DeleteSession(ctx context.Context, sessionID uuid.UUID) error

	GetSessionsByUserID(ctx context.Context, userID uuid.UUID) ([]*GourdianSessionType, error)

	GetActiveSessionsByUserID(ctx context.Context, userID uuid.UUID) ([]*GourdianSessionType, error)

	RevokeUserSessions(ctx context.Context, userID uuid.UUID) error

	RevokeSessionsExcept(ctx context.Context, userID, exceptSessionID uuid.UUID) error

	ExtendSession(ctx context.Context, sessionID uuid.UUID, duration time.Duration) error

	UpdateSessionActivity(ctx context.Context, sessionID uuid.UUID) error

	ValidateSessionByID(ctx context.Context, sessionID uuid.UUID) (*GourdianSessionType, error)

	ValidateSessionByIDIPUA(ctx context.Context, sessionID uuid.UUID, ipAddress, userAgent string) (*GourdianSessionType, error)

	SetSessionData(ctx context.Context, sessionID uuid.UUID, key string, value interface{}) error

	GetSessionData(ctx context.Context, sessionID uuid.UUID, key string) (interface{}, error)

	DeleteSessionData(ctx context.Context, sessionID uuid.UUID, key string) error

	SetTemporaryData(ctx context.Context, key string, value interface{}, ttl time.Duration) error

	GetTemporaryData(ctx context.Context, key string) (interface{}, error)

	DeleteTemporaryData(ctx context.Context, key string) error
}

const (
	sessionKeyPrefix       = "session:"
	userSessionsKeyPrefix  = "user_sessions:"
	sessionDataKeyPrefix   = "session_data:"
	tempDataKeyPrefix      = "temp_data:"
	sessionExpiryThreshold = 5 * time.Minute
)

type GurdianRedisSessionRepository struct {
	client *redis.Client
}

func NewGurdianRedisSessionRepository(client *redis.Client) GurdianSessionRepositoryInt {
	return &GurdianRedisSessionRepository{
		client: client,
	}
}

func (r *GurdianRedisSessionRepository) sessionKey(sessionID uuid.UUID) string {
	return sessionKeyPrefix + sessionID.String()
}

func (r *GurdianRedisSessionRepository) userSessionsKey(userID uuid.UUID) string {
	return userSessionsKeyPrefix + userID.String()
}

func (r *GurdianRedisSessionRepository) sessionDataKey(sessionID uuid.UUID) string {
	return sessionDataKeyPrefix + sessionID.String()
}

func (r *GurdianRedisSessionRepository) tempDataKey(key string) string {
	return tempDataKeyPrefix + key
}

func (r *GurdianRedisSessionRepository) CreateSession(ctx context.Context, session *GourdianSessionType) (*GourdianSessionType, error) {
	if session == nil {
		return nil, errs.RepositoryError("CreateSession", errs.ErrInvalidInput, "session cannot be nil")
	}

	// Check if session already exists
	exists, err := r.client.Exists(ctx, r.sessionKey(session.UUID)).Result()
	if err != nil {
		return nil, errs.RepositoryError("CreateSession", err, "failed to check session existence")
	}
	if exists > 0 {
		return nil, errs.RepositoryError("CreateSession", errs.ErrConflict, "session already exists")
	}

	// Serialize session
	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return nil, errs.RepositoryError("CreateSession", err, "failed to marshal session")
	}

	// Use transaction to ensure atomicity
	pipe := r.client.TxPipeline()
	pipe.Set(ctx, r.sessionKey(session.UUID), sessionJSON, time.Until(session.ExpiresAt))
	pipe.SAdd(ctx, r.userSessionsKey(session.UserID), session.UUID.String())
	pipe.ExpireAt(ctx, r.userSessionsKey(session.UserID), session.ExpiresAt)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return nil, errs.RepositoryError("CreateSession", err, "failed to store session in Redis")
	}

	return session, nil
}

func (r *GurdianRedisSessionRepository) RevokeSessionByID(ctx context.Context, sessionID uuid.UUID) error {
	session, err := r.GetSessionByID(ctx, sessionID)
	if err != nil {
		return err
	}

	session.Status = SessionStatusRevoked
	session.ExpiresAt = time.Now()

	_, err = r.UpdateSession(ctx, session)
	return err
}

func (r *GurdianRedisSessionRepository) GetSessionByID(ctx context.Context, sessionID uuid.UUID) (*GourdianSessionType, error) {
	sessionJSON, err := r.client.Get(ctx, r.sessionKey(sessionID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, errs.RepositoryError("GetSessionByID", errs.ErrNotFound, "session not found")
		}
		return nil, errs.RepositoryError("GetSessionByID", err, "failed to get session from Redis")
	}

	var session GourdianSessionType
	err = json.Unmarshal([]byte(sessionJSON), &session)
	if err != nil {
		return nil, errs.RepositoryError("GetSessionByID", err, "failed to unmarshal session")
	}

	// Check if session is expired
	if session.ExpiresAt.Before(time.Now()) {
		return nil, errs.RepositoryError("GetSessionByID", errs.ErrNotFound, "session expired")
	}

	return &session, nil
}

func (r *GurdianRedisSessionRepository) UpdateSession(ctx context.Context, session *GourdianSessionType) (*GourdianSessionType, error) {
	if session == nil {
		return nil, errs.RepositoryError("UpdateSession", errs.ErrInvalidInput, "session cannot be nil")
	}

	// Check if session exists first
	exists, err := r.client.Exists(ctx, r.sessionKey(session.UUID)).Result()
	if err != nil {
		return nil, errs.RepositoryError("UpdateSession", err, "failed to check session existence")
	}
	if exists == 0 {
		return nil, errs.RepositoryError("UpdateSession", errs.ErrNotFound, "session not found")
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return nil, errs.RepositoryError("UpdateSession", err, "failed to marshal session")
	}

	ttl := time.Until(session.ExpiresAt)
	if ttl < 0 {
		ttl = 0
	}

	err = r.client.Set(ctx, r.sessionKey(session.UUID), sessionJSON, ttl).Err()
	if err != nil {
		return nil, errs.RepositoryError("UpdateSession", err, "failed to update session in Redis")
	}

	return session, nil
}

func (r *GurdianRedisSessionRepository) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	session, err := r.GetSessionByID(ctx, sessionID)
	if err != nil {
		return err
	}

	pipe := r.client.TxPipeline()
	pipe.Del(ctx, r.sessionKey(sessionID))
	pipe.SRem(ctx, r.userSessionsKey(session.UserID), sessionID.String())
	pipe.Del(ctx, r.sessionDataKey(sessionID))

	_, err = pipe.Exec(ctx)
	if err != nil {
		return errs.RepositoryError("DeleteSession", err, "failed to delete session from Redis")
	}

	return nil
}

func (r *GurdianRedisSessionRepository) GetSessionsByUserID(ctx context.Context, userID uuid.UUID) ([]*GourdianSessionType, error) {
	sessionIDs, err := r.client.SMembers(ctx, r.userSessionsKey(userID)).Result()
	if err != nil {
		return nil, errs.RepositoryError("GetSessionsByUserID", err, "failed to get user sessions from Redis")
	}

	var sessions []*GourdianSessionType
	for _, sessionIDStr := range sessionIDs {
		sessionID, err := uuid.Parse(sessionIDStr)
		if err != nil {
			log.Printf("invalid session ID in user sessions set: %s", sessionIDStr)
			continue
		}

		session, err := r.GetSessionByID(ctx, sessionID)
		if err != nil {
			if errors.Is(err, errs.ErrNotFound) {
				// Clean up stale session reference
				_ = r.client.SRem(ctx, r.userSessionsKey(userID), sessionIDStr)
				continue
			}
			return nil, errs.RepositoryError("GetSessionsByUserID", err, fmt.Sprintf("failed to get session %s", sessionID))
		}

		sessions = append(sessions, session)
	}

	return sessions, nil
}

func (r *GurdianRedisSessionRepository) GetActiveSessionsByUserID(ctx context.Context, userID uuid.UUID) ([]*GourdianSessionType, error) {
	allSessions, err := r.GetSessionsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	var activeSessions []*GourdianSessionType
	for _, session := range allSessions {
		if session.Status == SessionStatusActive && session.ExpiresAt.After(time.Now()) {
			activeSessions = append(activeSessions, session)
		}
	}

	return activeSessions, nil
}

func (r *GurdianRedisSessionRepository) RevokeUserSessions(ctx context.Context, userID uuid.UUID) error {
	sessions, err := r.GetSessionsByUserID(ctx, userID)
	if err != nil {
		return err
	}

	for _, session := range sessions {
		if session.Status == SessionStatusActive {
			session.Status = SessionStatusRevoked
			session.ExpiresAt = time.Now()
			_, err = r.UpdateSession(ctx, session)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *GurdianRedisSessionRepository) RevokeSessionsExcept(ctx context.Context, userID, exceptSessionID uuid.UUID) error {
	sessions, err := r.GetSessionsByUserID(ctx, userID)
	if err != nil {
		return err
	}

	for _, session := range sessions {
		if session.UUID != exceptSessionID && session.Status == SessionStatusActive {
			session.Status = SessionStatusRevoked
			session.ExpiresAt = time.Now()
			_, err = r.UpdateSession(ctx, session)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *GurdianRedisSessionRepository) ExtendSession(ctx context.Context, sessionID uuid.UUID, duration time.Duration) error {
	session, err := r.GetSessionByID(ctx, sessionID)
	if err != nil {
		return err
	}

	if session.Status != SessionStatusActive {
		return errs.RepositoryError("ExtendSession", errs.ErrInvalidSession, "cannot extend inactive session")
	}

	session.ExpiresAt = time.Now().Add(duration)
	_, err = r.UpdateSession(ctx, session)
	return err
}

func (r *GurdianRedisSessionRepository) UpdateSessionActivity(ctx context.Context, sessionID uuid.UUID) error {
	session, err := r.GetSessionByID(ctx, sessionID)
	if err != nil {
		return err
	}

	session.LastActivity = time.Now()
	_, err = r.UpdateSession(ctx, session)
	return err
}

func (r *GurdianRedisSessionRepository) ValidateSessionByID(ctx context.Context, sessionID uuid.UUID) (*GourdianSessionType, error) {
	session, err := r.GetSessionByID(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	if session.Status != SessionStatusActive {
		return nil, errs.RepositoryError("ValidateSessionByID", errs.ErrInvalidSession, "session is not active")
	}

	if session.ExpiresAt.Before(time.Now()) {
		session.Status = SessionStatusExpired
		_, _ = r.UpdateSession(ctx, session) // Best effort update
		return nil, errs.RepositoryError("ValidateSessionByID", errs.ErrInvalidSession, "session has expired")
	}

	return session, nil
}

func (r *GurdianRedisSessionRepository) ValidateSessionByIDIPUA(ctx context.Context, sessionID uuid.UUID, ipAddress, userAgent string) (*GourdianSessionType, error) {
	session, err := r.ValidateSessionByID(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	if session.IPAddress != nil && *session.IPAddress != ipAddress {
		return nil, errs.RepositoryError("ValidateSessionByIDIPUA", errs.ErrInvalidSession, "IP address mismatch")
	}

	if session.UserAgent != nil && *session.UserAgent != userAgent {
		return nil, errs.RepositoryError("ValidateSessionByIDIPUA", errs.ErrInvalidSession, "user agent mismatch")
	}

	return session, nil
}

func (r *GurdianRedisSessionRepository) SetSessionData(ctx context.Context, sessionID uuid.UUID, key string, value interface{}) error {
	_, err := r.ValidateSessionByID(ctx, sessionID)
	if err != nil {
		return err
	}

	dataKey := r.sessionDataKey(sessionID)
	valueJSON, err := json.Marshal(value)
	if err != nil {
		return errs.RepositoryError("SetSessionData", err, "failed to marshal session data")
	}

	session, err := r.GetSessionByID(ctx, sessionID)
	if err != nil {
		return err
	}

	err = r.client.HSet(ctx, dataKey, key, valueJSON).Err()
	if err != nil {
		return errs.RepositoryError("SetSessionData", err, "failed to set session data in Redis")
	}

	// Set TTL on the hash if it doesn't exist yet
	ttl, err := r.client.TTL(ctx, dataKey).Result()
	if err != nil {
		return errs.RepositoryError("SetSessionData", err, "failed to check TTL for session data")
	}
	if ttl < 0 { // No TTL set
		err = r.client.ExpireAt(ctx, dataKey, session.ExpiresAt).Err()
		if err != nil {
			return errs.RepositoryError("SetSessionData", err, "failed to set TTL for session data")
		}
	}

	return nil
}

func (r *GurdianRedisSessionRepository) GetSessionData(ctx context.Context, sessionID uuid.UUID, key string) (interface{}, error) {
	_, err := r.ValidateSessionByID(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	valueJSON, err := r.client.HGet(ctx, r.sessionDataKey(sessionID), key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, errs.RepositoryError("GetSessionData", errs.ErrNotFound, "session data not found")
		}
		return nil, errs.RepositoryError("GetSessionData", err, "failed to get session data from Redis")
	}

	var value interface{}
	err = json.Unmarshal([]byte(valueJSON), &value)
	if err != nil {
		return nil, errs.RepositoryError("GetSessionData", err, "failed to unmarshal session data")
	}

	return value, nil
}

func (r *GurdianRedisSessionRepository) DeleteSessionData(ctx context.Context, sessionID uuid.UUID, key string) error {
	_, err := r.ValidateSessionByID(ctx, sessionID)
	if err != nil {
		return err
	}

	err = r.client.HDel(ctx, r.sessionDataKey(sessionID), key).Err()
	if err != nil {
		return errs.RepositoryError("DeleteSessionData", err, "failed to delete session data from Redis")
	}

	return nil
}

func (r *GurdianRedisSessionRepository) SetTemporaryData(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	valueJSON, err := json.Marshal(value)
	if err != nil {
		return errs.RepositoryError("SetTemporaryData", err, "failed to marshal temporary data")
	}

	err = r.client.Set(ctx, r.tempDataKey(key), valueJSON, ttl).Err()
	if err != nil {
		return errs.RepositoryError("SetTemporaryData", err, "failed to set temporary data in Redis")
	}

	return nil
}

func (r *GurdianRedisSessionRepository) GetTemporaryData(ctx context.Context, key string) (interface{}, error) {
	valueJSON, err := r.client.Get(ctx, r.tempDataKey(key)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, errs.RepositoryError("GetTemporaryData", errs.ErrNotFound, "temporary data not found")
		}
		return nil, errs.RepositoryError("GetTemporaryData", err, "failed to get temporary data from Redis")
	}

	var value interface{}
	err = json.Unmarshal([]byte(valueJSON), &value)
	if err != nil {
		return nil, errs.RepositoryError("GetTemporaryData", err, "failed to unmarshal temporary data")
	}

	return value, nil
}

func (r *GurdianRedisSessionRepository) DeleteTemporaryData(ctx context.Context, key string) error {
	err := r.client.Del(ctx, r.tempDataKey(key)).Err()
	if err != nil {
		return errs.RepositoryError("DeleteTemporaryData", err, "failed to delete temporary data from Redis")
	}

	return nil
}

type GourdianSessionConfig struct {
	MaxUserSessions            int
	MaxSessionsPerDevice       int
	MaxIPConnections           int
	AllowConcurrentSessions    bool
	TrackIPAddresses           bool
	TrackClientDevices         bool
	DefaultSessionDuration     time.Duration
	IdleTimeoutDuration        time.Duration
	SessionRenewalWindow       time.Duration
	SessionCleanupInterval     time.Duration
	AutoRevokeOnPasswordChange bool
	BlockedUserAgents          []string
}

type GourdianSessionServiceInt interface {
	CreateSession(ctx context.Context, userID uuid.UUID, username string, ipAddress, userAgent *string, roles []Role) (*GourdianSessionType, error)

	RevokeSession(ctx context.Context, sessionID uuid.UUID) error

	GetSession(ctx context.Context, sessionID uuid.UUID) (*GourdianSessionType, error)

	RefreshSession(ctx context.Context, sessionID uuid.UUID) (*GourdianSessionType, error)

	ExtendSession(ctx context.Context, sessionID uuid.UUID, duration time.Duration) (*GourdianSessionType, error)

	UpdateSessionActivity(ctx context.Context, sessionID uuid.UUID) error

	GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*GourdianSessionType, error)

	GetActiveUserSessions(ctx context.Context, userID uuid.UUID) ([]*GourdianSessionType, error)

	RevokeAllUserSessions(ctx context.Context, userID uuid.UUID) error

	RevokeOtherUserSessions(ctx context.Context, userID, currentSessionID uuid.UUID) error

	ValidateSession(ctx context.Context, sessionID uuid.UUID) (*GourdianSessionType, error)

	ValidateSessionWithContext(ctx context.Context, sessionID uuid.UUID, ipAddress, userAgent string) (*GourdianSessionType, error)

	SetSessionData(ctx context.Context, sessionID uuid.UUID, key string, value interface{}) error

	GetSessionData(ctx context.Context, sessionID uuid.UUID, key string) (interface{}, error)

	DeleteSessionData(ctx context.Context, sessionID uuid.UUID, key string) error

	SetTemporaryData(ctx context.Context, key string, value interface{}, ttl time.Duration) error

	GetTemporaryData(ctx context.Context, key string) (interface{}, error)

	DeleteTemporaryData(ctx context.Context, key string) error

	CheckSessionQuota(ctx context.Context, userID uuid.UUID, ipAddress, userAgent *string) error

	EnforceSessionLimits(ctx context.Context, userID uuid.UUID, ipAddress, userAgent *string) error
}

type GourdianSessionService struct {
	repo   GurdianSessionRepositoryInt
	config *GourdianSessionConfig
}

func NewGourdianSessionService(repo GurdianSessionRepositoryInt, config *GourdianSessionConfig) GourdianSessionServiceInt {

	return &GourdianSessionService{
		repo:   repo,
		config: config,
	}
}

// CreateSession creates a new session for the user with proper validation
func (s *GourdianSessionService) CreateSession(ctx context.Context, userID uuid.UUID, username string, ipAddress, userAgent *string, roles []Role) (*GourdianSessionType, error) {
	// Validate input
	if userID == uuid.Nil {
		return nil, errs.ServiceError("CreateSession", errs.ErrInvalidInput, "user ID cannot be empty")
	}
	if username == "" {
		return nil, errs.ServiceError("CreateSession", errs.ErrInvalidInput, "username cannot be empty")
	}

	// Check if user agent is blocked
	if userAgent != nil && s.isUserAgentBlocked(*userAgent) {
		return nil, errs.ServiceError("CreateSession", errs.ErrForbidden, "user agent is blocked")
	}

	// Enforce session limits
	if err := s.EnforceSessionLimits(ctx, userID, ipAddress, userAgent); err != nil {
		return nil, err
	}

	// Create new session object
	session := NewGurdianSessionObject(
		userID,
		username,
		ipAddress,
		userAgent,
		roles,
		s.config.DefaultSessionDuration,
	)

	// Store session
	createdSession, err := s.repo.CreateSession(ctx, session)
	if err != nil {
		return nil, errs.ServiceError("CreateSession", err, "failed to create session")
	}

	return createdSession, nil
}

// RevokeSession revokes a session by ID
func (s *GourdianSessionService) RevokeSession(ctx context.Context, sessionID uuid.UUID) error {
	if sessionID == uuid.Nil {
		return errs.ServiceError("RevokeSession", errs.ErrInvalidInput, "session ID cannot be empty")
	}

	err := s.repo.RevokeSessionByID(ctx, sessionID)
	if err != nil {
		return errs.ServiceError("RevokeSession", err, "failed to revoke session")
	}

	return nil
}

// GetSession retrieves a session by ID
func (s *GourdianSessionService) GetSession(ctx context.Context, sessionID uuid.UUID) (*GourdianSessionType, error) {
	if sessionID == uuid.Nil {
		return nil, errs.ServiceError("GetSession", errs.ErrInvalidInput, "session ID cannot be empty")
	}

	session, err := s.repo.GetSessionByID(ctx, sessionID)
	if err != nil {
		return nil, errs.ServiceError("GetSession", err, "failed to get session")
	}

	return session, nil
}

// RefreshSession refreshes a session if it's within the renewal window
func (s *GourdianSessionService) RefreshSession(ctx context.Context, sessionID uuid.UUID) (*GourdianSessionType, error) {
	if sessionID == uuid.Nil {
		return nil, errs.ServiceError("RefreshSession", errs.ErrInvalidInput, "session ID cannot be empty")
	}

	// Get and validate session
	session, err := s.ValidateSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	// Check if session is within renewal window
	renewalTime := session.ExpiresAt.Add(-s.config.SessionRenewalWindow)
	if time.Now().Before(renewalTime) {
		return session, nil
	}

	// Extend session
	newExpiry := time.Now().Add(s.config.DefaultSessionDuration)
	session.ExpiresAt = newExpiry
	session.LastActivity = time.Now()

	updatedSession, err := s.repo.UpdateSession(ctx, session)
	if err != nil {
		return nil, errs.ServiceError("RefreshSession", err, "failed to update session")
	}

	return updatedSession, nil
}

// ExtendSession extends a session's duration
func (s *GourdianSessionService) ExtendSession(ctx context.Context, sessionID uuid.UUID, duration time.Duration) (*GourdianSessionType, error) {
	if sessionID == uuid.Nil {
		return nil, errs.ServiceError("ExtendSession", errs.ErrInvalidInput, "session ID cannot be empty")
	}
	if duration <= 0 {
		return nil, errs.ServiceError("ExtendSession", errs.ErrInvalidInput, "duration must be positive")
	}

	// Get and validate session
	session, err := s.ValidateSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	// Extend session
	err = s.repo.ExtendSession(ctx, session.UUID, duration)
	if err != nil {
		return nil, errs.ServiceError("ExtendSession", err, "failed to extend session")
	}

	// Get updated session
	updatedSession, err := s.repo.GetSessionByID(ctx, sessionID)
	if err != nil {
		return nil, errs.ServiceError("ExtendSession", err, "failed to get updated session")
	}

	return updatedSession, nil
}

// UpdateSessionActivity updates the last activity time for a session
func (s *GourdianSessionService) UpdateSessionActivity(ctx context.Context, sessionID uuid.UUID) error {
	if sessionID == uuid.Nil {
		return errs.ServiceError("UpdateSessionActivity", errs.ErrInvalidInput, "session ID cannot be empty")
	}

	err := s.repo.UpdateSessionActivity(ctx, sessionID)
	if err != nil {
		return errs.ServiceError("UpdateSessionActivity", err, "failed to update session activity")
	}

	return nil
}

// GetUserSessions retrieves all sessions for a user
func (s *GourdianSessionService) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*GourdianSessionType, error) {
	if userID == uuid.Nil {
		return nil, errs.ServiceError("GetUserSessions", errs.ErrInvalidInput, "user ID cannot be empty")
	}

	sessions, err := s.repo.GetSessionsByUserID(ctx, userID)
	if err != nil {
		return nil, errs.ServiceError("GetUserSessions", err, "failed to get user sessions")
	}

	return sessions, nil
}

// GetActiveUserSessions retrieves active sessions for a user
func (s *GourdianSessionService) GetActiveUserSessions(ctx context.Context, userID uuid.UUID) ([]*GourdianSessionType, error) {
	if userID == uuid.Nil {
		return nil, errs.ServiceError("GetActiveUserSessions", errs.ErrInvalidInput, "user ID cannot be empty")
	}

	sessions, err := s.repo.GetActiveSessionsByUserID(ctx, userID)
	if err != nil {
		return nil, errs.ServiceError("GetActiveUserSessions", err, "failed to get active user sessions")
	}

	return sessions, nil
}

// RevokeAllUserSessions revokes all sessions for a user
func (s *GourdianSessionService) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID) error {
	if userID == uuid.Nil {
		return errs.ServiceError("RevokeAllUserSessions", errs.ErrInvalidInput, "user ID cannot be empty")
	}

	err := s.repo.RevokeUserSessions(ctx, userID)
	if err != nil {
		return errs.ServiceError("RevokeAllUserSessions", err, "failed to revoke user sessions")
	}

	return nil
}

// RevokeOtherUserSessions revokes all sessions for a user except the specified one
func (s *GourdianSessionService) RevokeOtherUserSessions(ctx context.Context, userID, currentSessionID uuid.UUID) error {
	if userID == uuid.Nil {
		return errs.ServiceError("RevokeOtherUserSessions", errs.ErrInvalidInput, "user ID cannot be empty")
	}
	if currentSessionID == uuid.Nil {
		return errs.ServiceError("RevokeOtherUserSessions", errs.ErrInvalidInput, "current session ID cannot be empty")
	}

	err := s.repo.RevokeSessionsExcept(ctx, userID, currentSessionID)
	if err != nil {
		return errs.ServiceError("RevokeOtherUserSessions", err, "failed to revoke other user sessions")
	}

	return nil
}

// ValidateSession validates a session by ID
func (s *GourdianSessionService) ValidateSession(ctx context.Context, sessionID uuid.UUID) (*GourdianSessionType, error) {
	if sessionID == uuid.Nil {
		return nil, errs.ServiceError("ValidateSession", errs.ErrInvalidInput, "session ID cannot be empty")
	}

	session, err := s.repo.ValidateSessionByID(ctx, sessionID)
	if err != nil {
		return nil, errs.ServiceError("ValidateSession", err, "session validation failed")
	}

	// Check idle timeout
	if s.config.IdleTimeoutDuration > 0 {
		idleCutoff := time.Now().Add(-s.config.IdleTimeoutDuration)
		if session.LastActivity.Before(idleCutoff) {
			// Mark session as expired due to inactivity
			session.Status = SessionStatusExpired
			_, _ = s.repo.UpdateSession(ctx, session) // Best effort update
			return nil, errs.ServiceError("ValidateSession", errs.ErrInvalidSession, "session expired due to inactivity")
		}
	}

	return session, nil
}

// ValidateSessionWithContext validates a session with additional IP and UserAgent checks
func (s *GourdianSessionService) ValidateSessionWithContext(ctx context.Context, sessionID uuid.UUID, ipAddress, userAgent string) (*GourdianSessionType, error) {
	if sessionID == uuid.Nil {
		return nil, errs.ServiceError("ValidateSessionWithContext", errs.ErrInvalidInput, "session ID cannot be empty")
	}
	if ipAddress == "" {
		return nil, errs.ServiceError("ValidateSessionWithContext", errs.ErrInvalidInput, "IP address cannot be empty")
	}
	if userAgent == "" {
		return nil, errs.ServiceError("ValidateSessionWithContext", errs.ErrInvalidInput, "user agent cannot be empty")
	}

	session, err := s.repo.ValidateSessionByIDIPUA(ctx, sessionID, ipAddress, userAgent)
	if err != nil {
		return nil, errs.ServiceError("ValidateSessionWithContext", err, "session validation failed")
	}

	// Check idle timeout
	if s.config.IdleTimeoutDuration > 0 {
		idleCutoff := time.Now().Add(-s.config.IdleTimeoutDuration)
		if session.LastActivity.Before(idleCutoff) {
			// Mark session as expired due to inactivity
			session.Status = SessionStatusExpired
			_, _ = s.repo.UpdateSession(ctx, session) // Best effort update
			return nil, errs.ServiceError("ValidateSessionWithContext", errs.ErrInvalidSession, "session expired due to inactivity")
		}
	}

	return session, nil
}

// SetSessionData stores data in the session
func (s *GourdianSessionService) SetSessionData(ctx context.Context, sessionID uuid.UUID, key string, value interface{}) error {
	if sessionID == uuid.Nil {
		return errs.ServiceError("SetSessionData", errs.ErrInvalidInput, "session ID cannot be empty")
	}
	if key == "" {
		return errs.ServiceError("SetSessionData", errs.ErrInvalidInput, "key cannot be empty")
	}

	// Validate session first
	_, err := s.ValidateSession(ctx, sessionID)
	if err != nil {
		return err
	}

	err = s.repo.SetSessionData(ctx, sessionID, key, value)
	if err != nil {
		return errs.ServiceError("SetSessionData", err, "failed to set session data")
	}

	return nil
}

// GetSessionData retrieves data from the session
func (s *GourdianSessionService) GetSessionData(ctx context.Context, sessionID uuid.UUID, key string) (interface{}, error) {
	if sessionID == uuid.Nil {
		return nil, errs.ServiceError("GetSessionData", errs.ErrInvalidInput, "session ID cannot be empty")
	}
	if key == "" {
		return nil, errs.ServiceError("GetSessionData", errs.ErrInvalidInput, "key cannot be empty")
	}

	// Validate session first
	_, err := s.ValidateSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	value, err := s.repo.GetSessionData(ctx, sessionID, key)
	if err != nil {
		return nil, errs.ServiceError("GetSessionData", err, "failed to get session data")
	}

	return value, nil
}

// DeleteSessionData removes data from the session
func (s *GourdianSessionService) DeleteSessionData(ctx context.Context, sessionID uuid.UUID, key string) error {
	if sessionID == uuid.Nil {
		return errs.ServiceError("DeleteSessionData", errs.ErrInvalidInput, "session ID cannot be empty")
	}
	if key == "" {
		return errs.ServiceError("DeleteSessionData", errs.ErrInvalidInput, "key cannot be empty")
	}

	// Validate session first
	_, err := s.ValidateSession(ctx, sessionID)
	if err != nil {
		return err
	}

	err = s.repo.DeleteSessionData(ctx, sessionID, key)
	if err != nil {
		return errs.ServiceError("DeleteSessionData", err, "failed to delete session data")
	}

	return nil
}

// SetTemporaryData stores temporary data with a TTL
func (s *GourdianSessionService) SetTemporaryData(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	if key == "" {
		return errs.ServiceError("SetTemporaryData", errs.ErrInvalidInput, "key cannot be empty")
	}
	if ttl <= 0 {
		return errs.ServiceError("SetTemporaryData", errs.ErrInvalidInput, "TTL must be positive")
	}

	err := s.repo.SetTemporaryData(ctx, key, value, ttl)
	if err != nil {
		return errs.ServiceError("SetTemporaryData", err, "failed to set temporary data")
	}

	return nil
}

// GetTemporaryData retrieves temporary data
func (s *GourdianSessionService) GetTemporaryData(ctx context.Context, key string) (interface{}, error) {
	if key == "" {
		return nil, errs.ServiceError("GetTemporaryData", errs.ErrInvalidInput, "key cannot be empty")
	}

	value, err := s.repo.GetTemporaryData(ctx, key)
	if err != nil {
		return nil, errs.ServiceError("GetTemporaryData", err, "failed to get temporary data")
	}

	return value, nil
}

// DeleteTemporaryData removes temporary data
func (s *GourdianSessionService) DeleteTemporaryData(ctx context.Context, key string) error {
	if key == "" {
		return errs.ServiceError("DeleteTemporaryData", errs.ErrInvalidInput, "key cannot be empty")
	}

	err := s.repo.DeleteTemporaryData(ctx, key)
	if err != nil {
		return errs.ServiceError("DeleteTemporaryData", err, "failed to delete temporary data")
	}

	return nil
}

// CheckSessionQuota checks if the user has reached their session quota
func (s *GourdianSessionService) CheckSessionQuota(ctx context.Context, userID uuid.UUID, ipAddress, userAgent *string) error {
	if userID == uuid.Nil {
		return errs.ServiceError("CheckSessionQuota", errs.ErrInvalidInput, "user ID cannot be empty")
	}

	// Check max sessions per user
	if s.config.MaxUserSessions > 0 {
		activeSessions, err := s.GetActiveUserSessions(ctx, userID)
		if err != nil {
			return errs.ServiceError("CheckSessionQuota", err, "failed to check active sessions")
		}

		if len(activeSessions) >= s.config.MaxUserSessions {
			return errs.ServiceError("CheckSessionQuota", errs.ErrForbidden, "maximum number of sessions reached for user")
		}
	}

	// Check max sessions per device (if tracking devices)
	if s.config.TrackClientDevices && s.config.MaxSessionsPerDevice > 0 && userAgent != nil {
		// Get all active sessions for this user agent
		allSessions, err := s.GetActiveUserSessions(ctx, userID)
		if err != nil {
			return errs.ServiceError("CheckSessionQuota", err, "failed to check device sessions")
		}

		deviceSessions := 0
		for _, session := range allSessions {
			if session.UserAgent != nil && *session.UserAgent == *userAgent {
				deviceSessions++
			}
		}

		if deviceSessions >= s.config.MaxSessionsPerDevice {
			return errs.ServiceError("CheckSessionQuota", errs.ErrForbidden, "maximum number of sessions reached for this device")
		}
	}

	// Check max IP connections (if tracking IPs)
	if s.config.TrackIPAddresses && s.config.MaxIPConnections > 0 && ipAddress != nil {
		// Get all active sessions for this IP
		allSessions, err := s.repo.GetActiveSessionsByUserID(ctx, userID)
		if err != nil {
			return errs.ServiceError("CheckSessionQuota", err, "failed to check IP sessions")
		}

		ipSessions := 0
		for _, session := range allSessions {
			if session.IPAddress != nil && *session.IPAddress == *ipAddress {
				ipSessions++
			}
		}

		if ipSessions >= s.config.MaxIPConnections {
			return errs.ServiceError("CheckSessionQuota", errs.ErrForbidden, "maximum number of connections reached from this IP")
		}
	}

	return nil
}

// EnforceSessionLimits enforces all session limits
func (s *GourdianSessionService) EnforceSessionLimits(ctx context.Context, userID uuid.UUID, ipAddress, userAgent *string) error {
	if userID == uuid.Nil {
		return errs.ServiceError("EnforceSessionLimits", errs.ErrInvalidInput, "user ID cannot be empty")
	}

	// Check all quotas
	if err := s.CheckSessionQuota(ctx, userID, ipAddress, userAgent); err != nil {
		return err
	}

	// Enforce concurrent sessions policy
	if !s.config.AllowConcurrentSessions {
		err := s.RevokeOtherUserSessions(ctx, userID, uuid.Nil)
		if err != nil {
			return errs.ServiceError("EnforceSessionLimits", err, "failed to enforce single session policy")
		}
	}

	return nil
}

// isUserAgentBlocked checks if the user agent is in the blocked list
func (s *GourdianSessionService) isUserAgentBlocked(userAgent string) bool {
	if len(s.config.BlockedUserAgents) == 0 {
		return false
	}

	uaLower := strings.ToLower(userAgent)
	for _, blockedUA := range s.config.BlockedUserAgents {
		if strings.Contains(uaLower, strings.ToLower(blockedUA)) {
			return true
		}
	}

	return false
}

// NewGourdianSession creates a new session service with Redis backend
func NewGourdianSession(redisClient *redis.Client, config *GourdianSessionConfig) GourdianSessionServiceInt {
	// Create the Redis repository
	redisRepo := NewGurdianRedisSessionRepository(redisClient)

	// Create and return the session service
	return NewGourdianSessionService(redisRepo, config)
}

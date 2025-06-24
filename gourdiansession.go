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
	"github.com/redis/go-redis/v9"
)

const (
	SessionStatusActive  string = "active"
	SessionStatusExpired string = "expired"
	SessionStatusRevoked string = "revoked"
)

var (
	ErrConflict       = errors.New("conflict")
	ErrNotFound       = errors.New("not found")
	ErrForbidden      = errors.New("forbidden")
	ErrInvalidInput   = errors.New("invalid input")
	ErrInvalidSession = errors.New("invalid session")
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

type GurdianSessionRedisRepository struct {
	client *redis.Client
}

func NewGurdianSessionRedisRepository(client *redis.Client) GurdianSessionRepositoryInt {
	return &GurdianSessionRedisRepository{
		client: client,
	}
}

func (r *GurdianSessionRedisRepository) sessionKey(sessionID uuid.UUID) string {
	return sessionKeyPrefix + sessionID.String()
}

func (r *GurdianSessionRedisRepository) userSessionsKey(userID uuid.UUID) string {
	return userSessionsKeyPrefix + userID.String()
}

func (r *GurdianSessionRedisRepository) sessionDataKey(sessionID uuid.UUID) string {
	return sessionDataKeyPrefix + sessionID.String()
}

func (r *GurdianSessionRedisRepository) tempDataKey(key string) string {
	return tempDataKeyPrefix + key
}

func (r *GurdianSessionRedisRepository) CreateSession(ctx context.Context, session *GourdianSessionType) (*GourdianSessionType, error) {
	if session == nil {
		return nil, fmt.Errorf("%w: session cannot be nil", ErrInvalidInput)
	}

	// Use WATCH to ensure atomic creation
	err := r.client.Watch(ctx, func(tx *redis.Tx) error {
		// Check if session already exists
		exists, err := tx.Exists(ctx, r.sessionKey(session.UUID)).Result()
		if err != nil {
			return fmt.Errorf("failed to check session existence: %w", err)
		}
		if exists > 0 {
			return fmt.Errorf("%w: session already exists", ErrConflict)
		}

		// Serialize session
		sessionJSON, err := json.Marshal(session)
		if err != nil {
			return fmt.Errorf("failed to marshal session: %w", err)
		}

		// Perform transaction
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Set(ctx, r.sessionKey(session.UUID), sessionJSON, time.Until(session.ExpiresAt))
			pipe.SAdd(ctx, r.userSessionsKey(session.UserID), session.UUID.String())
			pipe.ExpireAt(ctx, r.userSessionsKey(session.UserID), session.ExpiresAt)
			return nil
		})
		return err
	}, r.sessionKey(session.UUID))

	if errors.Is(err, redis.TxFailedErr) {
		return nil, fmt.Errorf("failed to create session: %w", ErrConflict)
	}
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (r *GurdianSessionRedisRepository) RevokeSessionByID(ctx context.Context, sessionID uuid.UUID) error {
	err := r.client.Watch(ctx, func(tx *redis.Tx) error {
		// Get current session
		sessionJSON, err := tx.Get(ctx, r.sessionKey(sessionID)).Result()
		if errors.Is(err, redis.Nil) {
			return fmt.Errorf("%w: session not found", ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("failed to get session: %w", err)
		}

		var session GourdianSessionType
		if err := json.Unmarshal([]byte(sessionJSON), &session); err != nil {
			return fmt.Errorf("failed to unmarshal session: %w", err)
		}

		// Only proceed if session is still active
		if session.Status != SessionStatusActive {
			return fmt.Errorf("%w: session is not active", ErrInvalidSession)
		}

		// Update session status
		session.Status = SessionStatusRevoked
		session.ExpiresAt = time.Now().Add(1 * time.Minute)

		updatedJSON, err := json.Marshal(session)
		if err != nil {
			return fmt.Errorf("failed to marshal session: %w", err)
		}

		// Perform transaction
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Set(ctx, r.sessionKey(sessionID), updatedJSON, time.Until(session.ExpiresAt))
			return nil
		})
		return err
	}, r.sessionKey(sessionID))

	if errors.Is(err, redis.TxFailedErr) {
		return fmt.Errorf("failed to revoke session: %w", ErrConflict)
	}
	return err
}

func (r *GurdianSessionRedisRepository) GetSessionByID(ctx context.Context, sessionID uuid.UUID) (*GourdianSessionType, error) {
	sessionJSON, err := r.client.Get(ctx, r.sessionKey(sessionID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, fmt.Errorf("%w: session not found", ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get session from Redis: %w", err)
	}

	var session GourdianSessionType
	err = json.Unmarshal([]byte(sessionJSON), &session)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	// Check if session is expired
	if session.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("%w: session has expired", ErrNotFound)
	}

	return &session, nil
}

func (r *GurdianSessionRedisRepository) UpdateSession(ctx context.Context, session *GourdianSessionType) (*GourdianSessionType, error) {
	if session == nil {
		return nil, fmt.Errorf("%w: session cannot be nil", ErrInvalidInput)
	}

	// Use WATCH for atomic update
	err := r.client.Watch(ctx, func(tx *redis.Tx) error {
		// Verify session still exists
		oldSessionJSON, err := tx.Get(ctx, r.sessionKey(session.UUID)).Result()
		if errors.Is(err, redis.Nil) {
			return fmt.Errorf("%w: session not found", ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("failed to get session: %w", err)
		}

		sessionJSON, err := json.Marshal(session)
		if err != nil {
			return fmt.Errorf("failed to marshal session: %w", err)
		}

		ttl := time.Until(session.ExpiresAt)
		if ttl < 0 {
			ttl = 0
		}

		// Perform transaction
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Set(ctx, r.sessionKey(session.UUID), sessionJSON, ttl)

			// Only update user sessions if UserID changed (though it probably shouldn't)
			var oldSession GourdianSessionType
			if err := json.Unmarshal([]byte(oldSessionJSON), &oldSession); err == nil {
				if oldSession.UserID != session.UserID {
					pipe.SRem(ctx, r.userSessionsKey(oldSession.UserID), session.UUID.String())
					pipe.SAdd(ctx, r.userSessionsKey(session.UserID), session.UUID.String())
					pipe.ExpireAt(ctx, r.userSessionsKey(session.UserID), session.ExpiresAt)
				}
			}
			return nil
		})
		return err
	}, r.sessionKey(session.UUID))

	if errors.Is(err, redis.TxFailedErr) {
		return nil, fmt.Errorf("failed to update session: %w", ErrConflict)
	}
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (r *GurdianSessionRedisRepository) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	// Use WATCH for atomic deletion
	err := r.client.Watch(ctx, func(tx *redis.Tx) error {
		// Get session first to get UserID
		sessionJSON, err := tx.Get(ctx, r.sessionKey(sessionID)).Result()
		if errors.Is(err, redis.Nil) {
			return fmt.Errorf("%w: session not found", ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("failed to get session: %w", err)
		}

		var session GourdianSessionType
		if err := json.Unmarshal([]byte(sessionJSON), &session); err != nil {
			return fmt.Errorf("failed to unmarshal session: %w", err)
		}

		// Perform transaction
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Del(ctx, r.sessionKey(sessionID))
			pipe.SRem(ctx, r.userSessionsKey(session.UserID), sessionID.String())
			pipe.Del(ctx, r.sessionDataKey(sessionID))
			return nil
		})
		return err
	}, r.sessionKey(sessionID))

	if errors.Is(err, redis.TxFailedErr) {
		return fmt.Errorf("failed to delete session: %w", ErrConflict)
	}
	return err
}

func (r *GurdianSessionRedisRepository) GetSessionsByUserID(ctx context.Context, userID uuid.UUID) ([]*GourdianSessionType, error) {
	sessionIDs, err := r.client.SMembers(ctx, r.userSessionsKey(userID)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions from Redis: %w", err)
	}

	var sessions []*GourdianSessionType
	var invalidSessionRefs []string

	for _, sessionIDStr := range sessionIDs {
		sessionID, err := uuid.Parse(sessionIDStr)
		if err != nil {
			invalidSessionRefs = append(invalidSessionRefs, sessionIDStr)
			continue
		}

		sessionJSON, err := r.client.Get(ctx, r.sessionKey(sessionID)).Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				invalidSessionRefs = append(invalidSessionRefs, sessionIDStr)
				continue
			}
			return nil, fmt.Errorf("failed to get session %s: %w", sessionID, err)
		}

		var session GourdianSessionType
		err = json.Unmarshal([]byte(sessionJSON), &session)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal session: %w", err)
		}

		sessions = append(sessions, &session)
	}

	// Clean up invalid session references in Redis
	if len(invalidSessionRefs) > 0 {
		_, err = r.client.SRem(ctx, r.userSessionsKey(userID), invalidSessionRefs).Result()
		if err != nil {
			log.Printf("failed to clean up invalid session references: %v", err)
		}
	}

	return sessions, nil
}

func (r *GurdianSessionRedisRepository) GetActiveSessionsByUserID(ctx context.Context, userID uuid.UUID) ([]*GourdianSessionType, error) {
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

func (r *GurdianSessionRedisRepository) RevokeUserSessions(ctx context.Context, userID uuid.UUID) error {
	// Get all session IDs first
	sessionIDs, err := r.client.SMembers(ctx, r.userSessionsKey(userID)).Result()
	if err != nil {
		return fmt.Errorf("failed to get user sessions: %w", err)
	}

	now := time.Now()
	for _, sessionIDStr := range sessionIDs {
		sessionID, err := uuid.Parse(sessionIDStr)
		if err != nil {
			continue
		}

		// Use WATCH for each session update
		err = r.client.Watch(ctx, func(tx *redis.Tx) error {
			// Get current session
			sessionJSON, err := tx.Get(ctx, r.sessionKey(sessionID)).Result()
			if errors.Is(err, redis.Nil) {
				return nil // Session already gone
			}
			if err != nil {
				return fmt.Errorf("failed to get session: %w", err)
			}

			var session GourdianSessionType
			if err := json.Unmarshal([]byte(sessionJSON), &session); err != nil {
				return fmt.Errorf("failed to unmarshal session: %w", err)
			}

			// Only revoke active sessions
			if session.Status != SessionStatusActive {
				return nil
			}

			// Update session
			session.Status = SessionStatusRevoked
			session.ExpiresAt = now.Add(1 * time.Minute)

			updatedJSON, err := json.Marshal(session)
			if err != nil {
				return fmt.Errorf("failed to marshal session: %w", err)
			}

			// Perform transaction
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, r.sessionKey(sessionID), updatedJSON, time.Until(session.ExpiresAt))
				return nil
			})
			return err
		}, r.sessionKey(sessionID))

		if errors.Is(err, redis.TxFailedErr) {
			log.Printf("Transaction failed for session %s, continuing with others", sessionID)
			continue
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *GurdianSessionRedisRepository) RevokeSessionsExcept(ctx context.Context, userID, exceptSessionID uuid.UUID) error {
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

func (r *GurdianSessionRedisRepository) ExtendSession(ctx context.Context, sessionID uuid.UUID, duration time.Duration) error {
	session, err := r.GetSessionByID(ctx, sessionID)
	if err != nil {
		return err
	}

	if session.Status != SessionStatusActive {
		return fmt.Errorf("%w: cannot extend inactive session", ErrInvalidSession)
	}

	session.ExpiresAt = session.ExpiresAt.Add(duration) // <-- Fixed: Add to existing expiration
	_, err = r.UpdateSession(ctx, session)
	return err
}

func (r *GurdianSessionRedisRepository) UpdateSessionActivity(ctx context.Context, sessionID uuid.UUID) error {
	session, err := r.GetSessionByID(ctx, sessionID)
	if err != nil {
		return err
	}

	session.LastActivity = time.Now()
	_, err = r.UpdateSession(ctx, session)
	return err
}

func (r *GurdianSessionRedisRepository) ValidateSessionByID(ctx context.Context, sessionID uuid.UUID) (*GourdianSessionType, error) {
	session, err := r.GetSessionByID(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	if session.Status != SessionStatusActive {
		return nil, fmt.Errorf("%w: session is not active", ErrInvalidSession)
	}

	if session.ExpiresAt.Before(time.Now()) {
		// Update session status to expired
		session.Status = SessionStatusExpired
		_, updateErr := r.UpdateSession(ctx, session)
		if updateErr != nil {
			// If we can't update, still return expired status but log the error
			log.Printf("failed to mark session as expired: %v", updateErr)
			return nil, fmt.Errorf("%w: session has expired", ErrInvalidSession)
		}
		return nil, fmt.Errorf("%w: session has expired", ErrInvalidSession)
	}

	return session, nil
}

func (r *GurdianSessionRedisRepository) ValidateSessionByIDIPUA(ctx context.Context, sessionID uuid.UUID, ipAddress, userAgent string) (*GourdianSessionType, error) {
	session, err := r.ValidateSessionByID(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	if session.IPAddress != nil && *session.IPAddress != ipAddress {
		return nil, fmt.Errorf("%w: IP address mismatch", ErrInvalidSession)
	}

	if session.UserAgent != nil && *session.UserAgent != userAgent {
		return nil, fmt.Errorf("%w: user agent mismatch", ErrInvalidSession)
	}

	return session, nil
}

func (r *GurdianSessionRedisRepository) SetSessionData(ctx context.Context, sessionID uuid.UUID, key string, value interface{}) error {
	// Use WATCH for atomic operation
	err := r.client.Watch(ctx, func(tx *redis.Tx) error {
		// Validate session exists and is active
		sessionJSON, err := tx.Get(ctx, r.sessionKey(sessionID)).Result()
		if errors.Is(err, redis.Nil) {
			return fmt.Errorf("%w: session not found", ErrNotFound)
		}
		if err != nil {
			return fmt.Errorf("failed to get session: %w", err)
		}

		var session GourdianSessionType
		if err := json.Unmarshal([]byte(sessionJSON), &session); err != nil {
			return fmt.Errorf("failed to unmarshal session: %w", err)
		}

		if session.Status != SessionStatusActive {
			return fmt.Errorf("%w: session is not active", ErrInvalidSession)
		}

		if session.ExpiresAt.Before(time.Now()) {
			return fmt.Errorf("%w: session has expired", ErrInvalidSession)
		}

		// Marshal data
		valueJSON, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("failed to marshal session data: %w", err)
		}

		dataKey := r.sessionDataKey(sessionID)

		// Perform transaction
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.HSet(ctx, dataKey, key, valueJSON)

			// Set TTL if not set
			ttl, err := pipe.TTL(ctx, dataKey).Result()
			if err != nil {
				return err
			}
			if ttl < 0 { // No TTL set
				pipe.ExpireAt(ctx, dataKey, session.ExpiresAt)
			}
			return nil
		})
		return err
	}, r.sessionKey(sessionID))

	if errors.Is(err, redis.TxFailedErr) {
		return fmt.Errorf("failed to set session data: %w", ErrConflict)
	}
	return err
}

func (r *GurdianSessionRedisRepository) GetSessionData(ctx context.Context, sessionID uuid.UUID, key string) (interface{}, error) {
	_, err := r.ValidateSessionByID(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	valueJSON, err := r.client.HGet(ctx, r.sessionDataKey(sessionID), key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, fmt.Errorf("%w: session data not found", ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get session data from Redis: %w", err)
	}

	var value interface{}
	err = json.Unmarshal([]byte(valueJSON), &value)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	return value, nil
}

func (r *GurdianSessionRedisRepository) DeleteSessionData(ctx context.Context, sessionID uuid.UUID, key string) error {
	_, err := r.ValidateSessionByID(ctx, sessionID)
	if err != nil {
		return err
	}

	err = r.client.HDel(ctx, r.sessionDataKey(sessionID), key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete session data from Redis: %w", err)
	}

	return nil
}

func (r *GurdianSessionRedisRepository) SetTemporaryData(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	valueJSON, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal temporary data: %w", err)
	}

	err = r.client.Set(ctx, r.tempDataKey(key), valueJSON, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to set temporary data in Redis: %w", err)
	}

	return nil
}

func (r *GurdianSessionRedisRepository) GetTemporaryData(ctx context.Context, key string) (interface{}, error) {
	valueJSON, err := r.client.Get(ctx, r.tempDataKey(key)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, fmt.Errorf("%w: temporary data not found", ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get temporary data from Redis: %w", err)
	}

	var value interface{}
	err = json.Unmarshal([]byte(valueJSON), &value)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal temporary data: %w", err)
	}

	return value, nil
}

func (r *GurdianSessionRedisRepository) DeleteTemporaryData(ctx context.Context, key string) error {
	err := r.client.Del(ctx, r.tempDataKey(key)).Err()
	if err != nil {
		return fmt.Errorf("failed to delete temporary data from Redis: %w", err)
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

func (s *GourdianSessionService) CreateSession(ctx context.Context, userID uuid.UUID, username string, ipAddress, userAgent *string, roles []Role) (*GourdianSessionType, error) {
	if userID == uuid.Nil {
		return nil, fmt.Errorf("%w: user ID cannot be empty", ErrInvalidInput)
	}
	if username == "" {
		return nil, fmt.Errorf("%w: username cannot be empty", ErrInvalidInput)
	}

	if userAgent != nil && s.isUserAgentBlocked(*userAgent) {
		return nil, fmt.Errorf("%w: user agent is blocked", ErrForbidden)
	}

	if err := s.EnforceSessionLimits(ctx, userID, ipAddress, userAgent); err != nil {
		return nil, err
	}

	session := NewGurdianSessionObject(
		userID,
		username,
		ipAddress,
		userAgent,
		roles,
		s.config.DefaultSessionDuration,
	)

	createdSession, err := s.repo.CreateSession(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return createdSession, nil
}

func (s *GourdianSessionService) RevokeSession(ctx context.Context, sessionID uuid.UUID) error {
	if sessionID == uuid.Nil {
		return fmt.Errorf("%w: session ID cannot be empty", ErrInvalidInput)
	}

	if err := s.repo.RevokeSessionByID(ctx, sessionID); err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}

	return nil
}

func (s *GourdianSessionService) GetSession(ctx context.Context, sessionID uuid.UUID) (*GourdianSessionType, error) {
	if sessionID == uuid.Nil {
		return nil, fmt.Errorf("%w: session ID cannot be empty", ErrInvalidInput)
	}

	session, err := s.repo.GetSessionByID(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return session, nil
}

func (s *GourdianSessionService) RefreshSession(ctx context.Context, sessionID uuid.UUID) (*GourdianSessionType, error) {
	session, err := s.ValidateSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	timeRemaining := session.ExpiresAt.Sub(now)

	// Debug log
	log.Printf("Now: %v, TimeRemaining: %v, RenewalWindow: %v", now, timeRemaining, s.config.SessionRenewalWindow)

	// Renew if we're within the renewal window
	if timeRemaining <= s.config.SessionRenewalWindow {
		newExpiry := now.Add(s.config.DefaultSessionDuration)
		log.Printf("Extending session from %v to %v", session.ExpiresAt, newExpiry)

		session.ExpiresAt = newExpiry
		session.LastActivity = now

		updated, err := s.repo.UpdateSession(ctx, session)
		if err != nil {
			return nil, fmt.Errorf("failed to update session: %w", err)
		}
		return updated, nil
	}

	return session, nil
}

func (s *GourdianSessionService) ExtendSession(ctx context.Context, sessionID uuid.UUID, duration time.Duration) (*GourdianSessionType, error) {
	if sessionID == uuid.Nil {
		return nil, fmt.Errorf("%w: session ID cannot be empty", ErrInvalidInput)
	}
	if duration <= 0 {
		return nil, fmt.Errorf("%w: duration must be positive", ErrInvalidInput)
	}

	session, err := s.ValidateSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	if err := s.repo.ExtendSession(ctx, session.UUID, duration); err != nil {
		return nil, fmt.Errorf("failed to extend session: %w", err)
	}

	updatedSession, err := s.repo.GetSessionByID(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get updated session: %w", err)
	}

	return updatedSession, nil
}

func (s *GourdianSessionService) UpdateSessionActivity(ctx context.Context, sessionID uuid.UUID) error {
	if sessionID == uuid.Nil {
		return fmt.Errorf("%w: session ID cannot be empty", ErrInvalidInput)
	}

	if err := s.repo.UpdateSessionActivity(ctx, sessionID); err != nil {
		return fmt.Errorf("failed to update session activity: %w", err)
	}

	return nil
}

func (s *GourdianSessionService) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*GourdianSessionType, error) {
	if userID == uuid.Nil {
		return nil, fmt.Errorf("%w: user ID cannot be empty", ErrInvalidInput)
	}

	sessions, err := s.repo.GetSessionsByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}

	return sessions, nil
}

func (s *GourdianSessionService) GetActiveUserSessions(ctx context.Context, userID uuid.UUID) ([]*GourdianSessionType, error) {
	if userID == uuid.Nil {
		return nil, fmt.Errorf("%w: user ID cannot be empty", ErrInvalidInput)
	}

	sessions, err := s.repo.GetActiveSessionsByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active user sessions: %w", err)
	}

	return sessions, nil
}

func (s *GourdianSessionService) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID) error {
	if userID == uuid.Nil {
		return fmt.Errorf("%w: user ID cannot be empty", ErrInvalidInput)
	}

	if err := s.repo.RevokeUserSessions(ctx, userID); err != nil {
		return fmt.Errorf("failed to revoke user sessions: %w", err)
	}

	return nil
}

func (s *GourdianSessionService) RevokeOtherUserSessions(ctx context.Context, userID, currentSessionID uuid.UUID) error {
	if userID == uuid.Nil {
		return fmt.Errorf("%w: user ID cannot be empty", ErrInvalidInput)
	}
	if currentSessionID == uuid.Nil {
		return fmt.Errorf("%w: current session ID cannot be empty", ErrInvalidInput)
	}

	if err := s.repo.RevokeSessionsExcept(ctx, userID, currentSessionID); err != nil {
		return fmt.Errorf("failed to revoke other user sessions: %w", err)
	}

	return nil
}

func (s *GourdianSessionService) ValidateSession(ctx context.Context, sessionID uuid.UUID) (*GourdianSessionType, error) {
	if sessionID == uuid.Nil {
		return nil, fmt.Errorf("%w: session ID cannot be empty", ErrInvalidInput)
	}

	session, err := s.repo.ValidateSessionByID(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("session validation failed: %w", err)
	}

	if s.config.IdleTimeoutDuration > 0 {
		idleCutoff := time.Now().Add(-s.config.IdleTimeoutDuration)
		if session.LastActivity.Before(idleCutoff) {
			session.Status = SessionStatusExpired
			_, _ = s.repo.UpdateSession(ctx, session)
			return nil, fmt.Errorf("%w: session expired due to inactivity", ErrInvalidSession)
		}
	}

	return session, nil
}

func (s *GourdianSessionService) ValidateSessionWithContext(ctx context.Context, sessionID uuid.UUID, ipAddress, userAgent string) (*GourdianSessionType, error) {
	if sessionID == uuid.Nil {
		return nil, fmt.Errorf("%w: session ID cannot be empty", ErrInvalidInput)
	}
	if ipAddress == "" {
		return nil, fmt.Errorf("%w: IP address cannot be empty", ErrInvalidInput)
	}
	if userAgent == "" {
		return nil, fmt.Errorf("%w: user agent cannot be empty", ErrInvalidInput)
	}

	session, err := s.repo.ValidateSessionByIDIPUA(ctx, sessionID, ipAddress, userAgent)
	if err != nil {
		return nil, fmt.Errorf("session validation failed: %w", err)
	}

	if s.config.IdleTimeoutDuration > 0 {
		idleCutoff := time.Now().Add(-s.config.IdleTimeoutDuration)
		if session.LastActivity.Before(idleCutoff) {
			session.Status = SessionStatusExpired
			_, _ = s.repo.UpdateSession(ctx, session)
			return nil, fmt.Errorf("%w: session expired due to inactivity", ErrInvalidSession)
		}
	}

	return session, nil
}

func (s *GourdianSessionService) SetSessionData(ctx context.Context, sessionID uuid.UUID, key string, value interface{}) error {
	if sessionID == uuid.Nil {
		return fmt.Errorf("%w: session ID cannot be empty", ErrInvalidInput)
	}
	if key == "" {
		return fmt.Errorf("%w: key cannot be empty", ErrInvalidInput)
	}

	if _, err := s.ValidateSession(ctx, sessionID); err != nil {
		return err
	}

	if err := s.repo.SetSessionData(ctx, sessionID, key, value); err != nil {
		return fmt.Errorf("failed to set session data: %w", err)
	}

	return nil
}

func (s *GourdianSessionService) GetSessionData(ctx context.Context, sessionID uuid.UUID, key string) (interface{}, error) {
	if sessionID == uuid.Nil {
		return nil, fmt.Errorf("%w: session ID cannot be empty", ErrInvalidInput)
	}
	if key == "" {
		return nil, fmt.Errorf("%w: key cannot be empty", ErrInvalidInput)
	}

	if _, err := s.ValidateSession(ctx, sessionID); err != nil {
		return nil, err
	}

	value, err := s.repo.GetSessionData(ctx, sessionID, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get session data: %w", err)
	}

	return value, nil
}

func (s *GourdianSessionService) DeleteSessionData(ctx context.Context, sessionID uuid.UUID, key string) error {
	if sessionID == uuid.Nil {
		return fmt.Errorf("%w: session ID cannot be empty", ErrInvalidInput)
	}
	if key == "" {
		return fmt.Errorf("%w: key cannot be empty", ErrInvalidInput)
	}

	if _, err := s.ValidateSession(ctx, sessionID); err != nil {
		return err
	}

	if err := s.repo.DeleteSessionData(ctx, sessionID, key); err != nil {
		return fmt.Errorf("failed to delete session data: %w", err)
	}

	return nil
}

func (s *GourdianSessionService) SetTemporaryData(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	if key == "" {
		return fmt.Errorf("%w: key cannot be empty", ErrInvalidInput)
	}
	if ttl <= 0 {
		return fmt.Errorf("%w: TTL must be positive", ErrInvalidInput)
	}

	if err := s.repo.SetTemporaryData(ctx, key, value, ttl); err != nil {
		return fmt.Errorf("failed to set temporary data: %w", err)
	}

	return nil
}

func (s *GourdianSessionService) GetTemporaryData(ctx context.Context, key string) (interface{}, error) {
	if key == "" {
		return nil, fmt.Errorf("%w: key cannot be empty", ErrInvalidInput)
	}

	value, err := s.repo.GetTemporaryData(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get temporary data: %w", err)
	}

	return value, nil
}

func (s *GourdianSessionService) DeleteTemporaryData(ctx context.Context, key string) error {
	if key == "" {
		return fmt.Errorf("%w: key cannot be empty", ErrInvalidInput)
	}

	if err := s.repo.DeleteTemporaryData(ctx, key); err != nil {
		return fmt.Errorf("failed to delete temporary data: %w", err)
	}

	return nil
}

func (s *GourdianSessionService) CheckSessionQuota(ctx context.Context, userID uuid.UUID, ipAddress, userAgent *string) error {
	if userID == uuid.Nil {
		return fmt.Errorf("%w: user ID cannot be empty", ErrInvalidInput)
	}

	if s.config.MaxUserSessions > 0 {
		activeSessions, err := s.GetActiveUserSessions(ctx, userID)
		if err != nil {
			return fmt.Errorf("failed to check active sessions: %w", err)
		}

		if len(activeSessions) >= s.config.MaxUserSessions {
			return fmt.Errorf("%w: maximum number of sessions reached for user", ErrForbidden)
		}
	}

	if s.config.TrackClientDevices && s.config.MaxSessionsPerDevice > 0 && userAgent != nil {
		allSessions, err := s.GetActiveUserSessions(ctx, userID)
		if err != nil {
			return fmt.Errorf("failed to check device sessions: %w", err)
		}

		deviceSessions := 0
		for _, session := range allSessions {
			if session.UserAgent != nil && *session.UserAgent == *userAgent {
				deviceSessions++
			}
		}

		if deviceSessions >= s.config.MaxSessionsPerDevice {
			return fmt.Errorf("%w: maximum number of sessions reached for this device", ErrForbidden)
		}
	}

	if s.config.TrackIPAddresses && s.config.MaxIPConnections > 0 && ipAddress != nil {
		allSessions, err := s.repo.GetActiveSessionsByUserID(ctx, userID)
		if err != nil {
			return fmt.Errorf("failed to check IP sessions: %w", err)
		}

		ipSessions := 0
		for _, session := range allSessions {
			if session.IPAddress != nil && *session.IPAddress == *ipAddress {
				ipSessions++
			}
		}

		if ipSessions >= s.config.MaxIPConnections {
			return fmt.Errorf("%w: maximum number of connections reached from this IP", ErrForbidden)
		}
	}

	return nil
}

func (s *GourdianSessionService) EnforceSessionLimits(ctx context.Context, userID uuid.UUID, ipAddress, userAgent *string) error {
	if userID == uuid.Nil {
		return fmt.Errorf("%w: user ID cannot be empty", ErrInvalidInput)
	}

	if err := s.CheckSessionQuota(ctx, userID, ipAddress, userAgent); err != nil {
		return err
	}

	if !s.config.AllowConcurrentSessions {
		// When creating a new session, we want to revoke ALL existing sessions
		if err := s.repo.RevokeUserSessions(ctx, userID); err != nil {
			return fmt.Errorf("failed to enforce single session policy: %w", err)
		}
	}

	return nil
}

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

func NewGourdianRedisSession(redisClient *redis.Client, config *GourdianSessionConfig) GourdianSessionServiceInt {
	redisRepo := NewGurdianSessionRedisRepository(redisClient)
	return NewGourdianSessionService(redisRepo, config)
}

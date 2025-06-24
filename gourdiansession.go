package gourdiansession

import (
	"context"
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

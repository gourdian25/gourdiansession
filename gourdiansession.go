// File: gourdiansession.go

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
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
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

type GourdianSessionMongoRepository struct {
	sessionsCollection *mongo.Collection
	tempDataCollection *mongo.Collection
	useTransactions    bool
}

func NewGourdianSessionMongoRepository(db *mongo.Database, useTransactions bool) GurdianSessionRepositoryInt {
	return &GourdianSessionMongoRepository{
		sessionsCollection: db.Collection("sessions"),
		tempDataCollection: db.Collection("temp_data"),
		useTransactions:    useTransactions,
	}
}

func (r *GourdianSessionMongoRepository) withTransaction(ctx context.Context, fn func(sessionCtx mongo.SessionContext) error) error {
	if !r.useTransactions {
		return fn(nil)
	}

	session, err := r.sessionsCollection.Database().Client().StartSession()
	if err != nil {
		return fmt.Errorf("failed to start session: %w", err)
	}
	defer session.EndSession(ctx)

	transactionFn := func(sessionCtx mongo.SessionContext) (interface{}, error) {
		return nil, fn(sessionCtx)
	}

	_, err = session.WithTransaction(ctx, transactionFn)
	return err
}

func (r *GourdianSessionMongoRepository) CreateSession(ctx context.Context, session *GourdianSessionType) (*GourdianSessionType, error) {
	if session == nil {
		return nil, fmt.Errorf("%w: session cannot be nil", ErrInvalidInput)
	}

	var createdSession *GourdianSessionType

	err := r.withTransaction(ctx, func(sessionCtx mongo.SessionContext) error {
		// Check for existing session with same UUID
		filter := bson.M{"uuid": session.UUID}
		count, err := r.sessionsCollection.CountDocuments(sessionCtx, filter)
		if err != nil {
			return fmt.Errorf("failed to check session existence: %w", err)
		}
		if count > 0 {
			return fmt.Errorf("%w: session already exists", ErrConflict)
		}

		// Insert new session with current timestamps
		session.CreatedAt = time.Now()
		session.LastActivity = time.Now()

		_, err = r.sessionsCollection.InsertOne(sessionCtx, session)
		if err != nil {
			if mongo.IsDuplicateKeyError(err) {
				return fmt.Errorf("%w: session with this UUID already exists", ErrConflict)
			}
			return fmt.Errorf("failed to create session: %w", err)
		}

		// Retrieve the created session to return
		createdSession, _ = r.GetSessionByID(sessionCtx, session.UUID)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return createdSession, nil
}

func (r *GourdianSessionMongoRepository) RevokeSessionByID(ctx context.Context, sessionID uuid.UUID) error {
	return r.withTransaction(ctx, func(sessionCtx mongo.SessionContext) error {
		// First get the session to ensure it exists and is active
		filter := bson.M{
			"uuid":   sessionID,
			"status": SessionStatusActive,
		}

		var session GourdianSessionType
		err := r.sessionsCollection.FindOne(sessionCtx, filter).Decode(&session)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				return fmt.Errorf("%w: active session not found", ErrNotFound)
			}
			return fmt.Errorf("failed to find session: %w", err)
		}

		// Update to revoke
		update := bson.M{
			"$set": bson.M{
				"status":       SessionStatusRevoked,
				"expiresAt":    time.Now().Add(1 * time.Minute),
				"updatedAt":    time.Now(),
				"lastActivity": time.Now(),
			},
		}

		_, err = r.sessionsCollection.UpdateByID(sessionCtx, session.ID, update)
		return err
	})
}

func (r *GourdianSessionMongoRepository) GetSessionByID(ctx context.Context, sessionID uuid.UUID) (*GourdianSessionType, error) {
	// Read operation doesn't need transaction
	filter := bson.M{"uuid": sessionID}

	var session GourdianSessionType
	err := r.sessionsCollection.FindOne(ctx, filter).Decode(&session)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("%w: session not found", ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return &session, nil
}

func (r *GourdianSessionMongoRepository) UpdateSession(ctx context.Context, session *GourdianSessionType) (*GourdianSessionType, error) {
	if session == nil {
		return nil, fmt.Errorf("%w: session cannot be nil", ErrInvalidInput)
	}

	var updatedSession *GourdianSessionType

	err := r.withTransaction(ctx, func(sessionCtx mongo.SessionContext) error {
		filter := bson.M{"uuid": session.UUID}

		// Ensure we don't update critical fields that shouldn't change
		update := bson.M{
			"$set": bson.M{
				"authenticated": session.Authenticated,
				"username":      session.Username,
				"status":        session.Status,
				"ipAddress":     session.IPAddress,
				"userAgent":     session.UserAgent,
				"roles":         session.Roles,
				"expiresAt":     session.ExpiresAt,
				"lastActivity":  session.LastActivity,
				"deletedAt":     session.DeletedAt,
				"updatedAt":     time.Now(),
			},
		}

		opts := options.FindOneAndUpdate().
			SetReturnDocument(options.After)

		err := r.sessionsCollection.FindOneAndUpdate(
			sessionCtx,
			filter,
			update,
			opts,
		).Decode(&updatedSession)

		if err != nil {
			if err == mongo.ErrNoDocuments {
				return fmt.Errorf("%w: session not found", ErrNotFound)
			}
			return fmt.Errorf("failed to update session: %w", err)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return updatedSession, nil
}

func (r *GourdianSessionMongoRepository) DeleteSession(ctx context.Context, sessionID uuid.UUID) error {
	return r.withTransaction(ctx, func(sessionCtx mongo.SessionContext) error {
		// First delete associated session data
		_, err := r.sessionsCollection.DeleteMany(
			sessionCtx,
			bson.M{"sessionId": sessionID},
		)
		if err != nil {
			return fmt.Errorf("failed to delete session data: %w", err)
		}

		// Then delete the session itself
		result, err := r.sessionsCollection.DeleteOne(
			sessionCtx,
			bson.M{"uuid": sessionID},
		)
		if err != nil {
			return fmt.Errorf("failed to delete session: %w", err)
		}

		if result.DeletedCount == 0 {
			return fmt.Errorf("%w: session not found", ErrNotFound)
		}

		return nil
	})
}

func (r *GourdianSessionMongoRepository) GetSessionsByUserID(ctx context.Context, userID uuid.UUID) ([]*GourdianSessionType, error) {
	// Read operation doesn't need transaction
	filter := bson.M{
		"userId":    userID,
		"deletedAt": nil, // Only non-deleted sessions
	}

	cursor, err := r.sessionsCollection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to find sessions: %w", err)
	}

	var sessions []*GourdianSessionType
	if err = cursor.All(ctx, &sessions); err != nil {
		return nil, fmt.Errorf("failed to decode sessions: %w", err)
	}

	// Filter out expired sessions
	var validSessions []*GourdianSessionType
	for _, session := range sessions {
		if session.ExpiresAt.After(time.Now()) {
			validSessions = append(validSessions, session)
		}
	}

	return validSessions, nil
}

func (r *GourdianSessionMongoRepository) GetActiveSessionsByUserID(ctx context.Context, userID uuid.UUID) ([]*GourdianSessionType, error) {
	filter := bson.M{
		"userId":    userID,
		"status":    SessionStatusActive,
		"deletedAt": bson.M{"$exists": false},
		"expiresAt": bson.M{"$gt": time.Now()},
	}

	cursor, err := r.sessionsCollection.Find(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to find active sessions: %w", err)
	}

	var sessions []*GourdianSessionType
	if err = cursor.All(ctx, &sessions); err != nil {
		return nil, fmt.Errorf("failed to decode active sessions: %w", err)
	}

	return sessions, nil
}

func (r *GourdianSessionMongoRepository) RevokeUserSessions(ctx context.Context, userID uuid.UUID) error {
	return r.withTransaction(ctx, func(sessionCtx mongo.SessionContext) error {
		now := time.Now()
		filter := bson.M{
			"userId":    userID,
			"status":    SessionStatusActive,
			"expiresAt": bson.M{"$gt": now},
			"deletedAt": nil,
		}

		update := bson.M{
			"$set": bson.M{
				"status":    SessionStatusRevoked,
				"expiresAt": now.Add(1 * time.Minute),
				"updatedAt": now,
			},
		}

		_, err := r.sessionsCollection.UpdateMany(sessionCtx, filter, update)
		if err != nil {
			return fmt.Errorf("failed to revoke user sessions: %w", err)
		}

		return nil
	})
}

func (r *GourdianSessionMongoRepository) RevokeSessionsExcept(ctx context.Context, userID, exceptSessionID uuid.UUID) error {
	return r.withTransaction(ctx, func(sessionCtx mongo.SessionContext) error {
		filter := bson.M{
			"userId":    userID,
			"uuid":      bson.M{"$ne": exceptSessionID},
			"status":    SessionStatusActive,
			"expiresAt": bson.M{"$gt": time.Now()},
			"deletedAt": bson.M{"$exists": false},
		}

		update := bson.M{
			"$set": bson.M{
				"status":    SessionStatusRevoked,
				"expiresAt": time.Now().Add(1 * time.Minute),
				"updatedAt": time.Now(),
			},
		}

		_, err := r.sessionsCollection.UpdateMany(sessionCtx, filter, update)
		if err != nil {
			return fmt.Errorf("failed to revoke other user sessions: %w", err)
		}

		return nil
	})
}

func (r *GourdianSessionMongoRepository) ExtendSession(ctx context.Context, sessionID uuid.UUID, duration time.Duration) error {
	return r.withTransaction(ctx, func(sessionCtx mongo.SessionContext) error {
		// First get the current session to check status
		session, err := r.GetSessionByID(sessionCtx, sessionID)
		if err != nil {
			return err
		}

		if session.Status != SessionStatusActive {
			return fmt.Errorf("%w: cannot extend inactive session", ErrInvalidSession)
		}

		newExpiry := time.Now().Add(duration)
		if newExpiry.Before(session.ExpiresAt) {
			return fmt.Errorf("%w: new duration would shorten existing session", ErrInvalidInput)
		}

		filter := bson.M{"uuid": sessionID}
		update := bson.M{
			"$set": bson.M{
				"expiresAt":    newExpiry,
				"lastActivity": time.Now(),
				"updatedAt":    time.Now(),
			},
		}

		_, err = r.sessionsCollection.UpdateOne(sessionCtx, filter, update)
		return err
	})
}

func (r *GourdianSessionMongoRepository) UpdateSessionActivity(ctx context.Context, sessionID uuid.UUID) error {
	filter := bson.M{"uuid": sessionID}
	update := bson.M{
		"$set": bson.M{
			"lastActivity": time.Now(),
			"updatedAt":    time.Now(),
		},
	}

	_, err := r.sessionsCollection.UpdateOne(ctx, filter, update)
	if err != nil {
		return fmt.Errorf("failed to update session activity: %w", err)
	}

	return nil
}

func (r *GourdianSessionMongoRepository) ValidateSessionByID(ctx context.Context, sessionID uuid.UUID) (*GourdianSessionType, error) {
	// This is a read operation but has side effects, so we use transaction
	var session *GourdianSessionType
	var validateErr error

	err := r.withTransaction(ctx, func(sessionCtx mongo.SessionContext) error {
		session, validateErr = r.GetSessionByID(sessionCtx, sessionID)
		if validateErr != nil {
			return validateErr
		}

		if session.Status != SessionStatusActive {
			validateErr = fmt.Errorf("%w: session is not active", ErrInvalidSession)
			return validateErr
		}

		if session.ExpiresAt.Before(time.Now()) {
			// Update session status to expired
			update := bson.M{
				"$set": bson.M{
					"status":    SessionStatusExpired,
					"updatedAt": time.Now(),
				},
			}

			_, updateErr := r.sessionsCollection.UpdateByID(
				sessionCtx,
				session.ID,
				update,
			)
			if updateErr != nil {
				log.Printf("failed to mark session as expired: %v", updateErr)
			}

			validateErr = fmt.Errorf("%w: session has expired", ErrInvalidSession)
			return validateErr
		}

		return nil
	})

	if err != nil {
		return nil, err
	}
	if validateErr != nil {
		return nil, validateErr
	}

	return session, nil
}

func (r *GourdianSessionMongoRepository) ValidateSessionByIDIPUA(ctx context.Context, sessionID uuid.UUID, ipAddress, userAgent string) (*GourdianSessionType, error) {
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

func (r *GourdianSessionMongoRepository) SetSessionData(ctx context.Context, sessionID uuid.UUID, key string, value interface{}) error {
	// Validate session exists and is active
	_, err := r.ValidateSessionByID(ctx, sessionID)
	if err != nil {
		return err
	}

	// Marshal the value to JSON
	valueJSON, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	// Create a composite key for the session data
	compositeKey := fmt.Sprintf("%s:%s", sessionID.String(), key)

	// Upsert the session data
	filter := bson.M{"key": compositeKey}
	update := bson.M{
		"$set": bson.M{
			"value":     valueJSON,
			"updatedAt": time.Now(),
		},
		"$setOnInsert": bson.M{
			"createdAt": time.Now(),
			"sessionId": sessionID,
		},
	}
	opts := options.Update().SetUpsert(true)

	_, err = r.sessionsCollection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		return fmt.Errorf("failed to set session data: %w", err)
	}

	return nil
}

func (r *GourdianSessionMongoRepository) GetSessionData(ctx context.Context, sessionID uuid.UUID, key string) (interface{}, error) {
	// Validate session exists and is active
	_, err := r.ValidateSessionByID(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	// Create a composite key for the session data
	compositeKey := fmt.Sprintf("%s:%s", sessionID.String(), key)

	filter := bson.M{"key": compositeKey}
	var result struct {
		Value []byte `bson:"value"`
	}

	err = r.sessionsCollection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("%w: session data not found", ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get session data: %w", err)
	}

	var value interface{}
	err = json.Unmarshal(result.Value, &value)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	return value, nil
}

func (r *GourdianSessionMongoRepository) DeleteSessionData(ctx context.Context, sessionID uuid.UUID, key string) error {
	// Validate session exists and is active
	_, err := r.ValidateSessionByID(ctx, sessionID)
	if err != nil {
		return err
	}

	// Create a composite key for the session data
	compositeKey := fmt.Sprintf("%s:%s", sessionID.String(), key)

	filter := bson.M{"key": compositeKey}
	_, err = r.sessionsCollection.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to delete session data: %w", err)
	}

	return nil
}

func (r *GourdianSessionMongoRepository) SetTemporaryData(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	// Marshal the value to JSON
	valueJSON, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal temporary data: %w", err)
	}

	// Create the document with TTL index
	doc := bson.M{
		"key":       key,
		"value":     valueJSON,
		"createdAt": time.Now(),
		"expiresAt": time.Now().Add(ttl),
		"updatedAt": time.Now(),
	}

	// Upsert the temporary data
	filter := bson.M{"key": key}
	update := bson.M{"$set": doc}
	opts := options.Update().SetUpsert(true)

	_, err = r.tempDataCollection.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		return fmt.Errorf("failed to set temporary data: %w", err)
	}

	return nil
}

func (r *GourdianSessionMongoRepository) GetTemporaryData(ctx context.Context, key string) (interface{}, error) {
	filter := bson.M{"key": key}
	var result struct {
		Value     []byte    `bson:"value"`
		ExpiresAt time.Time `bson:"expiresAt"`
	}

	err := r.tempDataCollection.FindOne(ctx, filter).Decode(&result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, fmt.Errorf("%w: temporary data not found", ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get temporary data: %w", err)
	}

	// Check if data is expired
	if result.ExpiresAt.Before(time.Now()) {
		// Delete expired data
		_, _ = r.tempDataCollection.DeleteOne(ctx, filter)
		return nil, fmt.Errorf("%w: temporary data has expired", ErrNotFound)
	}

	var value interface{}
	err = json.Unmarshal(result.Value, &value)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal temporary data: %w", err)
	}

	return value, nil
}

func (r *GourdianSessionMongoRepository) DeleteTemporaryData(ctx context.Context, key string) error {
	filter := bson.M{"key": key}
	_, err := r.tempDataCollection.DeleteOne(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to delete temporary data: %w", err)
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

func NewRedisGourdiansession(
	config *GourdianSessionConfig,
	redisClient *redis.Client,
) GourdianSessionServiceInt {
	redisRepo := NewGurdianSessionRedisRepository(redisClient)
	return NewGourdianSessionService(redisRepo, config)
}

func NewMongoGourdiansession(
	config *GourdianSessionConfig,
	mongoClient *mongo.Client,
	enableTransactions bool,
	dbName string,
) GourdianSessionServiceInt {
	db := mongoClient.Database(dbName)
	mongoRepo := NewGourdianSessionMongoRepository(db, enableTransactions)
	return NewGourdianSessionService(mongoRepo, config)
}

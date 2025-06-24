package gourdiansession

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

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

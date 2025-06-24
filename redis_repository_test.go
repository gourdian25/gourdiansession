// File: redis_repository_test.go

package gourdiansession

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedisRepository_DeleteSession(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	ctx := context.Background()

	t.Run("successful deletion", func(t *testing.T) {
		session := NewGurdianSessionObject(
			uuid.New(),
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)

		_, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		err = repo.DeleteSession(ctx, session.UUID)
		require.NoError(t, err)

		_, err = repo.GetSessionByID(ctx, session.UUID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session not found")
	})

	t.Run("delete non-existent session", func(t *testing.T) {
		err := repo.DeleteSession(ctx, uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session not found")
	})
}
func TestRedisRepository_SessionDataOperations(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	ctx := context.Background()

	session := NewGurdianSessionObject(
		uuid.New(),
		"testuser",
		nil,
		nil,
		[]Role{},
		30*time.Minute,
	)

	_, err := repo.CreateSession(ctx, session)
	require.NoError(t, err)

	t.Run("set and get session data", func(t *testing.T) {
		err := repo.SetSessionData(ctx, session.UUID, "testkey", "testvalue")
		require.NoError(t, err)

		val, err := repo.GetSessionData(ctx, session.UUID, "testkey")
		require.NoError(t, err)
		assert.Equal(t, "testvalue", val)
	})

	t.Run("get non-existent data", func(t *testing.T) {
		_, err := repo.GetSessionData(ctx, session.UUID, "nonexistent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session data not found")
	})

	t.Run("delete session data", func(t *testing.T) {
		err := repo.SetSessionData(ctx, session.UUID, "todelete", "value")
		require.NoError(t, err)

		err = repo.DeleteSessionData(ctx, session.UUID, "todelete")
		require.NoError(t, err)

		_, err = repo.GetSessionData(ctx, session.UUID, "todelete")
		require.Error(t, err)
	})
}

func TestRedisRepository_CreateSession(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	ctx := context.Background()

	t.Run("successful creation", func(t *testing.T) {
		session := NewGurdianSessionObject(
			uuid.New(),
			"testuser",
			strPtr("192.168.1.1"),
			strPtr("test-agent"),
			[]Role{},
			30*time.Minute,
		)

		created, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)
		assert.Equal(t, session.UUID, created.UUID)
		assert.Equal(t, SessionStatusActive, created.Status)

		// Verify Redis has the session
		stored, err := repo.GetSessionByID(ctx, session.UUID)
		require.NoError(t, err)
		assert.Equal(t, session.UUID, stored.UUID)
	})

	t.Run("nil session", func(t *testing.T) {
		_, err := repo.CreateSession(ctx, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session cannot be nil")
	})

	t.Run("duplicate session ID", func(t *testing.T) {
		session := NewGurdianSessionObject(
			uuid.New(),
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)

		_, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		// Try to create again with same UUID
		_, err = repo.CreateSession(ctx, session)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session already exists")
	})
}

func TestRedisRepository_GetSessionByID(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	ctx := context.Background()

	t.Run("existing session", func(t *testing.T) {
		session := NewGurdianSessionObject(
			uuid.New(),
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)

		_, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		retrieved, err := repo.GetSessionByID(ctx, session.UUID)
		require.NoError(t, err)
		assert.Equal(t, session.UUID, retrieved.UUID)
	})

	t.Run("non-existent session", func(t *testing.T) {
		_, err := repo.GetSessionByID(ctx, uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session not found")
	})

	t.Run("expired session", func(t *testing.T) {
		session := NewGurdianSessionObject(
			uuid.New(),
			"testuser",
			nil,
			nil,
			[]Role{},
			-1*time.Minute, // Already expired
		)

		_, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		// Redis may have already cleaned it up
		_, err = repo.GetSessionByID(ctx, session.UUID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session has expired")
	})
}

func TestRedisRepository_UpdateSession(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	ctx := context.Background()

	t.Run("successful update", func(t *testing.T) {
		session := NewGurdianSessionObject(
			uuid.New(),
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)

		_, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		session.Username = "updateduser"
		updated, err := repo.UpdateSession(ctx, session)
		require.NoError(t, err)
		assert.Equal(t, "updateduser", updated.Username)

		// Verify update in Redis
		stored, err := repo.GetSessionByID(ctx, session.UUID)
		require.NoError(t, err)
		assert.Equal(t, "updateduser", stored.Username)
	})

	t.Run("update non-existent session", func(t *testing.T) {
		session := NewGurdianSessionObject(
			uuid.New(),
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)

		_, err := repo.UpdateSession(ctx, session)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session not found")
	})
}

func TestRedisRepository_ValidateSession(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	ctx := context.Background()

	t.Run("valid session", func(t *testing.T) {
		session := NewGurdianSessionObject(
			uuid.New(),
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)

		_, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		validated, err := repo.ValidateSessionByID(ctx, session.UUID)
		require.NoError(t, err)
		assert.Equal(t, session.UUID, validated.UUID)
	})

	t.Run("revoked session", func(t *testing.T) {
		session := NewGurdianSessionObject(
			uuid.New(),
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)
		session.Status = SessionStatusRevoked

		_, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		_, err = repo.ValidateSessionByID(ctx, session.UUID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session is not active")
	})

	t.Run("expired session", func(t *testing.T) {
		// First create a valid session
		session := NewGurdianSessionObject(
			uuid.New(),
			"testuser",
			nil,
			nil,
			[]Role{},
			1*time.Minute, // Create with positive duration
		)

		_, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		// Manually set it to expired in Redis
		session.ExpiresAt = time.Now().Add(-1 * time.Minute)
		_, err = repo.UpdateSession(ctx, session)
		require.NoError(t, err)

		// Now validate should catch the expiration
		_, err = repo.ValidateSessionByID(ctx, session.UUID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session has expired")
	})
}

func TestRedisRepository_RevokeUserSessions(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	ctx := context.Background()

	userID := uuid.New()

	t.Run("revoke all sessions for user", func(t *testing.T) {
		// Create 3 active sessions for the user
		session1 := NewGurdianSessionObject(
			userID,
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)
		_, err := repo.CreateSession(ctx, session1)
		require.NoError(t, err)

		session2 := NewGurdianSessionObject(
			userID,
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)
		_, err = repo.CreateSession(ctx, session2)
		require.NoError(t, err)

		session3 := NewGurdianSessionObject(
			userID,
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)
		_, err = repo.CreateSession(ctx, session3)
		require.NoError(t, err)

		// Revoke all
		err = repo.RevokeUserSessions(ctx, userID)
		require.NoError(t, err)

		// Verify all sessions are revoked
		sessions, err := repo.GetSessionsByUserID(ctx, userID)
		require.NoError(t, err)
		for _, s := range sessions {
			assert.Equal(t, SessionStatusRevoked, s.Status)
		}
	})

	t.Run("revoke for user with no sessions", func(t *testing.T) {
		err := repo.RevokeUserSessions(ctx, uuid.New())
		require.NoError(t, err) // Should not error when no sessions exist
	})
}

func TestRedisRepository_RevokeSessionsExcept(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	ctx := context.Background()

	userID := uuid.New()

	t.Run("revoke all except one", func(t *testing.T) {
		// Create 3 sessions
		session1 := NewGurdianSessionObject(
			userID,
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)
		_, err := repo.CreateSession(ctx, session1)
		require.NoError(t, err)

		session2 := NewGurdianSessionObject(
			userID,
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)
		_, err = repo.CreateSession(ctx, session2)
		require.NoError(t, err)

		session3 := NewGurdianSessionObject(
			userID,
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)
		_, err = repo.CreateSession(ctx, session3)
		require.NoError(t, err)

		// Revoke all except session2
		err = repo.RevokeSessionsExcept(ctx, userID, session2.UUID)
		require.NoError(t, err)

		// Verify
		sessions, err := repo.GetSessionsByUserID(ctx, userID)
		require.NoError(t, err)
		for _, s := range sessions {
			if s.UUID == session2.UUID {
				assert.Equal(t, SessionStatusActive, s.Status)
			} else {
				assert.Equal(t, SessionStatusRevoked, s.Status)
			}
		}
	})

	t.Run("except session doesn't exist", func(t *testing.T) {
		session := NewGurdianSessionObject(
			userID,
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)
		_, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		// Try to revoke all except non-existent session
		err = repo.RevokeSessionsExcept(ctx, userID, uuid.New())
		require.NoError(t, err) // Should still work, just revoke all

		// Verify all sessions are revoked
		sessions, err := repo.GetSessionsByUserID(ctx, userID)
		require.NoError(t, err)
		for _, s := range sessions {
			assert.Equal(t, SessionStatusRevoked, s.Status)
		}
	})
}

func TestRedisRepository_UpdateSessionActivity(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	ctx := context.Background()

	t.Run("update activity", func(t *testing.T) {
		session := NewGurdianSessionObject(
			uuid.New(),
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)

		_, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		originalActivity := session.LastActivity
		time.Sleep(10 * time.Millisecond) // Ensure time advances

		err = repo.UpdateSessionActivity(ctx, session.UUID)
		require.NoError(t, err)

		// Verify last activity was updated
		updated, err := repo.GetSessionByID(ctx, session.UUID)
		require.NoError(t, err)
		assert.True(t, updated.LastActivity.After(originalActivity))
	})

	t.Run("update non-existent session", func(t *testing.T) {
		err := repo.UpdateSessionActivity(ctx, uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session not found")
	})
}

func TestRedisRepository_ValidateSessionByIDIPUA(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	ctx := context.Background()

	t.Run("successful validation with IP/UA", func(t *testing.T) {
		ip := "192.168.1.1"
		ua := "test-agent"
		session := NewGurdianSessionObject(
			uuid.New(),
			"testuser",
			&ip,
			&ua,
			[]Role{},
			30*time.Minute,
		)

		_, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		validated, err := repo.ValidateSessionByIDIPUA(ctx, session.UUID, ip, ua)
		require.NoError(t, err)
		assert.Equal(t, session.UUID, validated.UUID)
	})

	t.Run("IP mismatch", func(t *testing.T) {
		ip := "192.168.1.1"
		ua := "test-agent"
		session := NewGurdianSessionObject(
			uuid.New(),
			"testuser",
			&ip,
			&ua,
			[]Role{},
			30*time.Minute,
		)

		_, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		_, err = repo.ValidateSessionByIDIPUA(ctx, session.UUID, "10.0.0.1", ua)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "IP address mismatch")
	})

	t.Run("UA mismatch", func(t *testing.T) {
		ip := "192.168.1.1"
		ua := "test-agent"
		session := NewGurdianSessionObject(
			uuid.New(),
			"testuser",
			&ip,
			&ua,
			[]Role{},
			30*time.Minute,
		)

		_, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		_, err = repo.ValidateSessionByIDIPUA(ctx, session.UUID, ip, "different-agent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user agent mismatch")
	})

	t.Run("session without IP/UA tracking", func(t *testing.T) {
		session := NewGurdianSessionObject(
			uuid.New(),
			"testuser",
			nil, // No IP
			nil, // No UA
			[]Role{},
			30*time.Minute,
		)

		_, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		// Should pass validation even with random IP/UA since session doesn't track them
		validated, err := repo.ValidateSessionByIDIPUA(ctx, session.UUID, "1.2.3.4", "some-agent")
		require.NoError(t, err)
		assert.Equal(t, session.UUID, validated.UUID)
	})
}

func TestRedisRepository_TemporaryDataOperations(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	ctx := context.Background()

	t.Run("set and get temporary data", func(t *testing.T) {
		err := repo.SetTemporaryData(ctx, "testkey", "testvalue", 1*time.Minute)
		require.NoError(t, err)

		val, err := repo.GetTemporaryData(ctx, "testkey")
		require.NoError(t, err)
		assert.Equal(t, "testvalue", val)
	})

	t.Run("get non-existent temporary data", func(t *testing.T) {
		_, err := repo.GetTemporaryData(ctx, "nonexistent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "temporary data not found")
	})

	t.Run("delete temporary data", func(t *testing.T) {
		err := repo.SetTemporaryData(ctx, "todelete", "value", 1*time.Minute)
		require.NoError(t, err)

		err = repo.DeleteTemporaryData(ctx, "todelete")
		require.NoError(t, err)

		_, err = repo.GetTemporaryData(ctx, "todelete")
		require.Error(t, err)
	})

	t.Run("temporary data expiration", func(t *testing.T) {
		err := repo.SetTemporaryData(ctx, "tempkey", "tempvalue", 100*time.Millisecond)
		require.NoError(t, err)

		// Immediately get should work
		val, err := repo.GetTemporaryData(ctx, "tempkey")
		require.NoError(t, err)
		assert.Equal(t, "tempvalue", val)

		// Wait for expiration
		time.Sleep(150 * time.Millisecond)

		// Now should be expired
		_, err = repo.GetTemporaryData(ctx, "tempkey")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "temporary data not found")
	})
}

func TestRedisRepository_ExtendSession(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	ctx := context.Background()

	t.Run("successful extension", func(t *testing.T) {
		session := NewGurdianSessionObject(
			uuid.New(),
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)

		_, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		originalExpiry := session.ExpiresAt
		extension := 1 * time.Hour

		err = repo.ExtendSession(ctx, session.UUID, extension)
		require.NoError(t, err)

		// Verify the session was extended
		updated, err := repo.GetSessionByID(ctx, session.UUID)
		require.NoError(t, err)
		assert.True(t, updated.ExpiresAt.After(originalExpiry))
		assert.WithinDuration(t, originalExpiry.Add(extension), updated.ExpiresAt, time.Second)
	})

	t.Run("extend non-existent session", func(t *testing.T) {
		err := repo.ExtendSession(ctx, uuid.New(), 1*time.Hour)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session not found")
	})

	t.Run("extend revoked session", func(t *testing.T) {
		session := NewGurdianSessionObject(
			uuid.New(),
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)
		session.Status = SessionStatusRevoked

		_, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		err = repo.ExtendSession(ctx, session.UUID, 1*time.Hour)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot extend inactive session")
	})
}

func TestRedisRepository_RevokeSessionByID(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	ctx := context.Background()

	t.Run("successful revocation", func(t *testing.T) {
		session := NewGurdianSessionObject(
			uuid.New(),
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)

		_, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		err = repo.RevokeSessionByID(ctx, session.UUID)
		require.NoError(t, err)

		// Verify session is revoked but still retrievable
		stored, err := repo.GetSessionByID(ctx, session.UUID)
		require.NoError(t, err)
		assert.Equal(t, SessionStatusRevoked, stored.Status)
		assert.True(t, stored.ExpiresAt.After(time.Now()))
		assert.True(t, stored.ExpiresAt.Before(time.Now().Add(2*time.Minute)))
	})

	t.Run("revoke non-existent session", func(t *testing.T) {
		err := repo.RevokeSessionByID(ctx, uuid.New())
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrNotFound), "Expected ErrNotFound")
		assert.Contains(t, err.Error(), "session not found")
	})

	t.Run("revoke already revoked session", func(t *testing.T) {
		session := NewGurdianSessionObject(
			uuid.New(),
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)
		session.Status = SessionStatusRevoked

		_, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		err = repo.RevokeSessionByID(ctx, session.UUID)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidSession), "Expected ErrInvalidSession")
		assert.Contains(t, err.Error(), "session is not active")
	})

	// t.Run("concurrent revocation conflict", func(t *testing.T) {
	// 	session := NewGurdianSessionObject(
	// 		uuid.New(),
	// 		"testuser",
	// 		nil,
	// 		nil,
	// 		[]Role{},
	// 		30*time.Minute,
	// 	)

	// 	_, err := repo.CreateSession(ctx, session)
	// 	require.NoError(t, err)

	// 	// Simulate concurrent modification by changing the session externally
	// 	session.Status = SessionStatusRevoked
	// 	updatedJSON, err := json.Marshal(session)
	// 	require.NoError(t, err)
	// 	err = client.Set(ctx, repo.sessionKey(session.UUID), updatedJSON, 0).Err()
	// 	require.NoError(t, err)

	// 	// Now attempt to revoke
	// 	err = repo.RevokeSessionByID(ctx, session.UUID)
	// 	require.Error(t, err)
	// 	assert.True(t, errors.Is(err, ErrConflict) ||
	// 		errors.Is(err, ErrInvalidSession),
	// 		"Expected conflict or invalid session error")
	// })
}

func TestRedisRepository_GetSessionsByUserID(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	ctx := context.Background()

	userID := uuid.New()

	t.Run("no sessions for user", func(t *testing.T) {
		sessions, err := repo.GetSessionsByUserID(ctx, userID)
		require.NoError(t, err)
		assert.Empty(t, sessions)
	})

	t.Run("multiple sessions for user", func(t *testing.T) {
		// Create 3 sessions for the same user
		session1 := NewGurdianSessionObject(
			userID,
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)
		_, err := repo.CreateSession(ctx, session1)
		require.NoError(t, err)

		session2 := NewGurdianSessionObject(
			userID,
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)
		_, err = repo.CreateSession(ctx, session2)
		require.NoError(t, err)

		session3 := NewGurdianSessionObject(
			userID,
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)
		_, err = repo.CreateSession(ctx, session3)
		require.NoError(t, err)

		// Get all sessions
		sessions, err := repo.GetSessionsByUserID(ctx, userID)
		require.NoError(t, err)
		assert.Len(t, sessions, 3)

		// Verify all sessions belong to the same user
		for _, s := range sessions {
			assert.Equal(t, userID, s.UserID)
		}
	})

}

func TestRedisRepository_ConcurrentSessionOperations(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	ctx := context.Background()

	userID := uuid.New()
	session := NewGurdianSessionObject(
		userID,
		"testuser",
		nil,
		nil,
		[]Role{},
		30*time.Minute,
	)

	t.Run("concurrent creates", func(t *testing.T) {
		// Create the session first
		_, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		// Try to create again concurrently
		errChan := make(chan error, 1)
		go func() {
			_, err := repo.CreateSession(ctx, session)
			errChan <- err
		}()

		err = <-errChan
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session already exists")
	})

	t.Run("concurrent updates", func(t *testing.T) {
		// Reset session
		err := client.FlushDB(ctx).Err()
		require.NoError(t, err)

		// Create initial session
		_, err = repo.CreateSession(ctx, session)
		require.NoError(t, err)

		// Concurrent updates
		update1 := *session
		update1.Username = "update1"

		update2 := *session
		update2.Username = "update2"

		errChan := make(chan error, 2)
		go func() {
			_, err := repo.UpdateSession(ctx, &update1)
			errChan <- err
		}()
		go func() {
			_, err := repo.UpdateSession(ctx, &update2)
			errChan <- err
		}()

		// Wait for both updates to complete
		err1 := <-errChan
		err2 := <-errChan

		// One should succeed, the other might fail or overwrite
		if err1 == nil && err2 == nil {
			// Both succeeded, check which update "won"
			updated, err := repo.GetSessionByID(ctx, session.UUID)
			require.NoError(t, err)
			assert.True(t, updated.Username == "update1" || updated.Username == "update2")
		} else {
			// One failed
			assert.True(t, err1 != nil || err2 != nil)
		}
	})
}

func TestRedisRepository_NilInputHandling(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	ctx := context.Background()

	t.Run("nil IP and UA", func(t *testing.T) {
		session := NewGurdianSessionObject(
			uuid.New(),
			"testuser",
			nil, // nil IP
			nil, // nil UA
			[]Role{},
			30*time.Minute,
		)

		_, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		// Should be able to validate with any IP/UA
		validated, err := repo.ValidateSessionByIDIPUA(ctx, session.UUID, "1.2.3.4", "some-agent")
		require.NoError(t, err)
		assert.Equal(t, session.UUID, validated.UUID)
	})

	t.Run("empty roles", func(t *testing.T) {
		session := NewGurdianSessionObject(
			uuid.New(),
			"testuser",
			nil,
			nil,
			nil, // empty roles
			30*time.Minute,
		)

		_, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		retrieved, err := repo.GetSessionByID(ctx, session.UUID)
		require.NoError(t, err)
		assert.Empty(t, retrieved.Roles)
	})
}

func TestRedisRepository_UserSessionTracking(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	ctx := context.Background()

	user1 := uuid.New()
	user2 := uuid.New()

	t.Run("multiple users sessions", func(t *testing.T) {
		// Create 2 sessions for user1
		session1 := NewGurdianSessionObject(
			user1,
			"user1",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)
		_, err := repo.CreateSession(ctx, session1)
		require.NoError(t, err)

		session2 := NewGurdianSessionObject(
			user1,
			"user1",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)
		_, err = repo.CreateSession(ctx, session2)
		require.NoError(t, err)

		// Create 1 session for user2
		session3 := NewGurdianSessionObject(
			user2,
			"user2",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)
		_, err = repo.CreateSession(ctx, session3)
		require.NoError(t, err)

		// Verify counts
		user1Sessions, err := repo.GetSessionsByUserID(ctx, user1)
		require.NoError(t, err)
		assert.Len(t, user1Sessions, 2)

		user2Sessions, err := repo.GetSessionsByUserID(ctx, user2)
		require.NoError(t, err)
		assert.Len(t, user2Sessions, 1)
	})
}

// Add these tests to your repository_test.go file

func TestRedisRepository_GetSessionsByUserID_EdgeCases(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	ctx := context.Background()

	t.Run("handle invalid session IDs in set", func(t *testing.T) {
		userID := uuid.New()
		userSessionsKey := "user_sessions:" + userID.String()

		// Add invalid session ID to the set
		err := client.SAdd(ctx, userSessionsKey, "invalid-uuid").Err()
		require.NoError(t, err)

		// Verify the invalid ID is initially present
		membersBefore, err := client.SMembers(ctx, userSessionsKey).Result()
		require.NoError(t, err)
		assert.Contains(t, membersBefore, "invalid-uuid")

		// Call GetSessionsByUserID which should clean up invalid IDs
		sessions, err := repo.GetSessionsByUserID(ctx, userID)
		require.NoError(t, err)
		assert.Empty(t, sessions)

		// Verify the invalid ID was cleaned up
		membersAfter, err := client.SMembers(ctx, userSessionsKey).Result()
		require.NoError(t, err)
		assert.NotContains(t, membersAfter, "invalid-uuid")
	})

	t.Run("handle stale session references", func(t *testing.T) {
		userID := uuid.New()
		sessionID := uuid.New()
		userSessionsKey := "user_sessions:" + userID.String()

		// Add reference to non-existent session
		err := client.SAdd(ctx, userSessionsKey, sessionID.String()).Err()
		require.NoError(t, err)

		// Verify the reference is initially present
		membersBefore, err := client.SMembers(ctx, userSessionsKey).Result()
		require.NoError(t, err)
		assert.Contains(t, membersBefore, sessionID.String())

		// Call GetSessionsByUserID which should clean up stale references
		sessions, err := repo.GetSessionsByUserID(ctx, userID)
		require.NoError(t, err)
		assert.Empty(t, sessions)

		// Verify the stale reference was cleaned up
		membersAfter, err := client.SMembers(ctx, userSessionsKey).Result()
		require.NoError(t, err)
		assert.NotContains(t, membersAfter, sessionID.String())
	})
}

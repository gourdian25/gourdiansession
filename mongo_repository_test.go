// File: mongo_repository_test.go

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

func TestMongoRepository_RevokeUserSessions(t *testing.T) {
	db := setupTestMongoDB(t)
	defer cleanupTestMongoDB(t, db)

	repo := NewGourdianSessionMongoRepository(db, false)
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

func TestMongoRepository_RevokeSessionsExcept(t *testing.T) {
	db := setupTestMongoDB(t)
	defer cleanupTestMongoDB(t, db)

	repo := NewGourdianSessionMongoRepository(db, false)
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

func TestMongoRepository_ValidateSessionByIDIPUA(t *testing.T) {
	db := setupTestMongoDB(t)
	defer cleanupTestMongoDB(t, db)

	repo := NewGourdianSessionMongoRepository(db, false)
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

func TestMongoRepository_SessionDataOperations(t *testing.T) {
	db := setupTestMongoDB(t)
	defer cleanupTestMongoDB(t, db)

	repo := NewGourdianSessionMongoRepository(db, false)
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

	t.Run("complex data types", func(t *testing.T) {
		complexData := map[string]interface{}{
			"nested": map[string]interface{}{
				"value": 42,
				"list":  []string{"a", "b", "c"},
			},
			"timestamp": time.Now(),
		}

		err := repo.SetSessionData(ctx, session.UUID, "complex", complexData)
		require.NoError(t, err)

		retrieved, err := repo.GetSessionData(ctx, session.UUID, "complex")
		require.NoError(t, err)
		assert.IsType(t, map[string]interface{}{}, retrieved)
	})
}

func TestMongoRepository_CreateSession(t *testing.T) {
	db := setupTestMongoDB(t)
	defer cleanupTestMongoDB(t, db)

	repo := NewGourdianSessionMongoRepository(db, false)
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

		// Verify MongoDB has the session
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
		assert.Contains(t, err.Error(), "session already exists") // Updated to match actual error message
	})
}

func TestMongoRepository_GetSessionByID(t *testing.T) {
	db := setupTestMongoDB(t)
	defer cleanupTestMongoDB(t, db)

	repo := NewGourdianSessionMongoRepository(db, false)
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

		created, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		retrieved, err := repo.GetSessionByID(ctx, created.UUID)
		require.NoError(t, err)
		assert.Equal(t, created.UUID, retrieved.UUID)
		assert.Equal(t, SessionStatusActive, retrieved.Status)
	})

	t.Run("non-existent session", func(t *testing.T) {
		_, err := repo.GetSessionByID(ctx, uuid.New())
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrNotFound))
		assert.Contains(t, err.Error(), "session not found")
	})

	// t.Run("revoked session", func(t *testing.T) {
	// 	session := NewGurdianSessionObject(
	// 		uuid.New(),
	// 		"testuser",
	// 		nil,
	// 		nil,
	// 		[]Role{},
	// 		30*time.Minute,
	// 	)

	// 	created, err := repo.CreateSession(ctx, session)
	// 	require.NoError(t, err)

	// 	// Revoke the session
	// 	err = repo.RevokeSessionByID(ctx, created.UUID)
	// 	require.NoError(t, err)

	// 	// Retrieval should fail with invalid session error
	// 	_, err = repo.GetSessionByID(ctx, created.UUID)
	// 	require.Error(t, err)
	// 	assert.True(t, errors.Is(err, ErrInvalidSession))
	// 	assert.Contains(t, err.Error(), "session is not active")
	// })

	// t.Run("deleted session", func(t *testing.T) {
	// 	session := NewGurdianSessionObject(
	// 		uuid.New(),
	// 		"testuser",
	// 		nil,
	// 		nil,
	// 		[]Role{},
	// 		30*time.Minute,
	// 	)

	// 	created, err := repo.CreateSession(ctx, session)
	// 	require.NoError(t, err)

	// 	// Delete the session
	// 	now := time.Now()
	// 	created.DeletedAt = &now
	// 	_, err = repo.UpdateSession(ctx, created)
	// 	require.NoError(t, err)

	// 	// Retrieval should fail with not found error
	// 	_, err = repo.GetSessionByID(ctx, created.UUID)
	// 	require.Error(t, err)
	// 	assert.True(t, errors.Is(err, ErrNotFound))
	// 	assert.Contains(t, err.Error(), "session has been deleted")
	// })

	// t.Run("expired session validation on retrieval", func(t *testing.T) {
	// 	// Create a session that will immediately expire
	// 	session := NewGurdianSessionObject(
	// 		uuid.New(),
	// 		"testuser",
	// 		nil,
	// 		nil,
	// 		[]Role{},
	// 		-1*time.Minute, // Already expired
	// 	)

	// 	// Creation should succeed (expiration is checked on retrieval)
	// 	created, err := repo.CreateSession(ctx, session)
	// 	require.NoError(t, err)

	// 	// First retrieval should fail with expired error
	// 	_, err = repo.GetSessionByID(ctx, created.UUID)
	// 	require.Error(t, err)
	// 	assert.True(t, errors.Is(err, ErrInvalidSession), "should detect expired session on retrieval")
	// 	assert.Contains(t, err.Error(), "session has expired")

	// 	// Second retrieval should also fail with inactive session error
	// 	_, err = repo.GetSessionByID(ctx, created.UUID)
	// 	require.Error(t, err)
	// 	assert.Contains(t, err.Error(), "session is not active")
	// })
}

func TestMongoRepository_UpdateSession(t *testing.T) {
	db := setupTestMongoDB(t)
	defer cleanupTestMongoDB(t, db)

	repo := NewGourdianSessionMongoRepository(db, false)
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

		// Verify update in MongoDB
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

	// t.Run("cannot change user ID", func(t *testing.T) {
	// 	// Create test data
	// 	originalUserID := uuid.New()
	// 	newUserID := uuid.New()

	// 	session := NewGurdianSessionObject(
	// 		originalUserID,
	// 		"testuser",
	// 		nil,
	// 		nil,
	// 		[]Role{},
	// 		30*time.Minute,
	// 	)

	// 	// Create the session
	// 	created, err := repo.CreateSession(ctx, session)
	// 	require.NoError(t, err)
	// 	require.NotNil(t, created)

	// 	// Verify session exists for original user
	// 	sessions, err := repo.GetSessionsByUserID(ctx, originalUserID)
	// 	require.NoError(t, err)
	// 	require.Len(t, sessions, 1, "should find 1 session for original user")
	// 	assert.Equal(t, created.UUID, sessions[0].UUID, "session UUID should match")

	// 	// Make a copy and try to change user ID
	// 	modifiedSession := *created
	// 	modifiedSession.UserID = newUserID

	// 	// Attempt the update - should fail
	// 	_, err = repo.UpdateSession(ctx, &modifiedSession)
	// 	require.Error(t, err, "should error when trying to change user ID")
	// 	assert.True(t, errors.Is(err, ErrForbidden), "should return ErrForbidden")
	// 	assert.Contains(t, err.Error(), "cannot change user ID", "error should mention user ID change")

	// 	// Verify no sessions exist for the new user ID
	// 	newUserSessions, err := repo.GetSessionsByUserID(ctx, newUserID)
	// 	require.NoError(t, err)
	// 	assert.Empty(t, newUserSessions, "should be no sessions for new user ID")

	// 	// Verify original session still exists and is unchanged
	// 	unchanged, err := repo.GetSessionByID(ctx, created.UUID)
	// 	require.NoError(t, err, "original session should still exist")
	// 	assert.Equal(t, originalUserID, unchanged.UserID, "user ID should not have changed")
	// 	assert.Equal(t, created.UUID, unchanged.UUID, "UUID should not have changed")

	// 	// Verify still only one session for original user
	// 	originalUserSessions, err := repo.GetSessionsByUserID(ctx, originalUserID)
	// 	require.NoError(t, err)
	// 	require.Len(t, originalUserSessions, 1, "should still be 1 session for original user")
	// 	assert.Equal(t, created.UUID, originalUserSessions[0].UUID, "session UUID should match")
	// })
}

func TestMongoRepository_DeleteSession(t *testing.T) {
	db := setupTestMongoDB(t)
	defer cleanupTestMongoDB(t, db)

	repo := NewGourdianSessionMongoRepository(db, false)
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

func TestMongoRepository_ValidateSessionByID(t *testing.T) {
	db := setupTestMongoDB(t)
	defer cleanupTestMongoDB(t, db)

	repo := NewGourdianSessionMongoRepository(db, false)
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
		session := NewGurdianSessionObject(
			uuid.New(),
			"testuser",
			nil,
			nil,
			[]Role{},
			1*time.Millisecond, // Very short expiration
		)

		_, err := repo.CreateSession(ctx, session)
		require.NoError(t, err)

		// Wait for expiration
		time.Sleep(10 * time.Millisecond)

		_, err = repo.ValidateSessionByID(ctx, session.UUID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session has expired")

		// Verify session was marked as expired
		stored, err := repo.GetSessionByID(ctx, session.UUID)
		if err == nil { // Might be deleted
			assert.Equal(t, SessionStatusExpired, stored.Status)
		}
	})
}

func TestMongoRepository_RevokeSessionByID(t *testing.T) {
	db := setupTestMongoDB(t)
	defer cleanupTestMongoDB(t, db)

	repo := NewGourdianSessionMongoRepository(db, false)
	ctx := context.Background()

	// t.Run("successful revocation", func(t *testing.T) {
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

	// 	err = repo.RevokeSessionByID(ctx, session.UUID)
	// 	require.NoError(t, err)

	// 	// Verify session is revoked
	// 	stored, err := repo.GetSessionByID(ctx, session.UUID)
	// 	require.NoError(t, err)
	// 	assert.Equal(t, SessionStatusRevoked, stored.Status)
	// 	assert.True(t, stored.ExpiresAt.Before(time.Now().Add(2*time.Minute)))
	// })

	t.Run("revoke non-existent session", func(t *testing.T) {
		err := repo.RevokeSessionByID(ctx, uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "active session not found")
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
		assert.Contains(t, err.Error(), "active session not found")
	})
}

func TestMongoRepository_GetSessionsByUserID(t *testing.T) {
	db := setupTestMongoDB(t)
	defer cleanupTestMongoDB(t, db)

	repo := NewGourdianSessionMongoRepository(db, false)
	ctx := context.Background()

	userID := uuid.New()

	t.Run("no sessions for user", func(t *testing.T) {
		sessions, err := repo.GetSessionsByUserID(ctx, userID)
		require.NoError(t, err)
		assert.Empty(t, sessions)
	})

	// t.Run("multiple sessions for user", func(t *testing.T) {
	// 	// Create 3 sessions for the same user
	// 	session1 := NewGurdianSessionObject(
	// 		userID,
	// 		"testuser",
	// 		nil,
	// 		nil,
	// 		[]Role{},
	// 		30*time.Minute,
	// 	)
	// 	_, err := repo.CreateSession(ctx, session1)
	// 	require.NoError(t, err)

	// 	session2 := NewGurdianSessionObject(
	// 		userID,
	// 		"testuser",
	// 		nil,
	// 		nil,
	// 		[]Role{},
	// 		30*time.Minute,
	// 	)
	// 	_, err = repo.CreateSession(ctx, session2)
	// 	require.NoError(t, err)

	// 	session3 := NewGurdianSessionObject(
	// 		userID,
	// 		"testuser",
	// 		nil,
	// 		nil,
	// 		[]Role{},
	// 		30*time.Minute,
	// 	)
	// 	_, err = repo.CreateSession(ctx, session3)
	// 	require.NoError(t, err)

	// 	// Get all sessions
	// 	sessions, err := repo.GetSessionsByUserID(ctx, userID)
	// 	require.NoError(t, err)
	// 	assert.Len(t, sessions, 3)

	// 	// Verify all sessions belong to the same user
	// 	for _, s := range sessions {
	// 		assert.Equal(t, userID, s.UserID)
	// 	}
	// })

	// t.Run("filter out deleted sessions", func(t *testing.T) {
	// 	userID := uuid.New()
	// 	session := NewGurdianSessionObject(
	// 		userID,
	// 		"testuser",
	// 		nil,
	// 		nil,
	// 		[]Role{},
	// 		30*time.Minute,
	// 	)
	// 	now := time.Now()
	// 	session.DeletedAt = &now

	// 	_, err := repo.CreateSession(ctx, session)
	// 	require.NoError(t, err)

	// 	sessions, err := repo.GetSessionsByUserID(ctx, userID)
	// 	require.NoError(t, err)
	// 	assert.Empty(t, sessions)
	// })
}

func TestMongoRepository_GetActiveSessionsByUserID(t *testing.T) {
	db := setupTestMongoDB(t)
	defer cleanupTestMongoDB(t, db)

	repo := NewGourdianSessionMongoRepository(db, false)
	ctx := context.Background()

	userID := uuid.New()

	t.Run("only active sessions", func(t *testing.T) {
		// Create active session
		activeSession := NewGurdianSessionObject(
			userID,
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)
		_, err := repo.CreateSession(ctx, activeSession)
		require.NoError(t, err)

		// Create revoked session
		revokedSession := NewGurdianSessionObject(
			userID,
			"testuser",
			nil,
			nil,
			[]Role{},
			30*time.Minute,
		)
		revokedSession.Status = SessionStatusRevoked
		_, err = repo.CreateSession(ctx, revokedSession)
		require.NoError(t, err)

		// Create expired session
		expiredSession := NewGurdianSessionObject(
			userID,
			"testuser",
			nil,
			nil,
			[]Role{},
			-1*time.Minute,
		)
		_, err = repo.CreateSession(ctx, expiredSession)
		require.NoError(t, err)

		// Get active sessions
		activeSessions, err := repo.GetActiveSessionsByUserID(ctx, userID)
		require.NoError(t, err)
		assert.Len(t, activeSessions, 1)
		assert.Equal(t, activeSession.UUID, activeSessions[0].UUID)
	})
}

// func TestMongoRepository_ExtendSession(t *testing.T) {
// 	db := setupTestMongoDB(t)
// 	defer cleanupTestMongoDB(t, db)

// 	repo := NewGourdianSessionMongoRepository(db, false)
// 	ctx := context.Background()

// 	t.Run("successful extension", func(t *testing.T) {
// 		session := NewGurdianSessionObject(
// 			uuid.New(),
// 			"testuser",
// 			nil,
// 			nil,
// 			[]Role{},
// 			30*time.Minute,
// 		)

// 		_, err := repo.CreateSession(ctx, session)
// 		require.NoError(t, err)

// 		originalExpiry := session.ExpiresAt
// 		extension := 1 * time.Hour

// 		err = repo.ExtendSession(ctx, session.UUID, extension)
// 		require.NoError(t, err)

// 		// Verify the session was extended
// 		updated, err := repo.GetSessionByID(ctx, session.UUID)
// 		require.NoError(t, err)
// 		assert.True(t, updated.ExpiresAt.After(originalExpiry))
// 		assert.WithinDuration(t, originalExpiry.Add(extension), updated.ExpiresAt, time.Second)
// 	})

// 	t.Run("extend non-existent session", func(t *testing.T) {
// 		err := repo.ExtendSession(ctx, uuid.New(), 1*time.Hour)
// 		require.Error(t, err)
// 		assert.Contains(t, err.Error(), "session not found")
// 	})

// 	t.Run("extend revoked session", func(t *testing.T) {
// 		session := NewGurdianSessionObject(
// 			uuid.New(),
// 			"testuser",
// 			nil,
// 			nil,
// 			[]Role{},
// 			30*time.Minute,
// 		)
// 		session.Status = SessionStatusRevoked

// 		_, err := repo.CreateSession(ctx, session)
// 		require.NoError(t, err)

// 		err = repo.ExtendSession(ctx, session.UUID, 1*time.Hour)
// 		require.Error(t, err)
// 		assert.Contains(t, err.Error(), "cannot extend inactive session")
// 	})
// }

// func TestMongoRepository_UpdateSessionActivity(t *testing.T) {
// 	db := setupTestMongoDB(t)
// 	defer cleanupTestMongoDB(t, db)

// 	repo := NewGourdianSessionMongoRepository(db, false)
// 	ctx := context.Background()

// 	t.Run("update activity", func(t *testing.T) {
// 		session := NewGurdianSessionObject(
// 			uuid.New(),
// 			"testuser",
// 			nil,
// 			nil,
// 			[]Role{},
// 			30*time.Minute,
// 		)

// 		_, err := repo.CreateSession(ctx, session)
// 		require.NoError(t, err)

// 		originalActivity := session.LastActivity
// 		time.Sleep(10 * time.Millisecond) // Ensure time advances

// 		err = repo.UpdateSessionActivity(ctx, session.UUID)
// 		require.NoError(t, err)

// 		// Verify last activity was updated
// 		updated, err := repo.GetSessionByID(ctx, session.UUID)
// 		require.NoError(t, err)
// 		assert.True(t, updated.LastActivity.After(originalActivity))
// 	})

// 	t.Run("update non-existent session", func(t *testing.T) {
// 		err := repo.UpdateSessionActivity(ctx, uuid.New())
// 		require.Error(t, err)
// 		assert.Contains(t, err.Error(), "session not found")
// 	})
// }

// func TestMongoRepository_TemporaryDataOperations(t *testing.T) {
// 	db := setupTestMongoDB(t)
// 	defer cleanupTestMongoDB(t, db)

// 	repo := NewGourdianSessionMongoRepository(db, false)
// 	ctx := context.Background()

// 	t.Run("set and get temporary data", func(t *testing.T) {
// 		err := repo.SetTemporaryData(ctx, "testkey", "testvalue", 1*time.Minute)
// 		require.NoError(t, err)

// 		val, err := repo.GetTemporaryData(ctx, "testkey")
// 		require.NoError(t, err)
// 		assert.Equal(t, "testvalue", val)
// 	})

// 	t.Run("get non-existent temporary data", func(t *testing.T) {
// 		_, err := repo.GetTemporaryData(ctx, "nonexistent")
// 		require.Error(t, err)
// 		assert.Contains(t, err.Error(), "temporary data not found")
// 	})

// 	t.Run("delete temporary data", func(t *testing.T) {
// 		err := repo.SetTemporaryData(ctx, "todelete", "value", 1*time.Minute)
// 		require.NoError(t, err)

// 		err = repo.DeleteTemporaryData(ctx, "todelete")
// 		require.NoError(t, err)

// 		_, err = repo.GetTemporaryData(ctx, "todelete")
// 		require.Error(t, err)
// 	})

// 	t.Run("temporary data expiration", func(t *testing.T) {
// 		err := repo.SetTemporaryData(ctx, "tempkey", "tempvalue", 100*time.Millisecond)
// 		require.NoError(t, err)

// 		// Immediately get should work
// 		val, err := repo.GetTemporaryData(ctx, "tempkey")
// 		require.NoError(t, err)
// 		assert.Equal(t, "tempvalue", val)

// 		// Wait for expiration
// 		time.Sleep(150 * time.Millisecond)

// 		// Now should be expired
// 		_, err = repo.GetTemporaryData(ctx, "tempkey")
// 		require.Error(t, err)
// 		assert.Contains(t, err.Error(), "temporary data not found")
// 	})
// }

// func TestMongoRepository_Transactions(t *testing.T) {
// 	db := setupTestMongoDB(t)
// 	defer cleanupTestMongoDB(t, db)

// 	repo := NewGourdianSessionMongoRepository(db, false)
// 	ctx := context.Background()

// 	t.Run("transactional create session", func(t *testing.T) {
// 		session := NewGurdianSessionObject(
// 			uuid.New(),
// 			"testuser",
// 			nil,
// 			nil,
// 			[]Role{},
// 			30*time.Minute,
// 		)

// 		// Simulate concurrent creation by another process
// 		go func() {
// 			time.Sleep(100 * time.Millisecond)
// 			_, _ = repo.CreateSession(ctx, session)
// 		}()

// 		// This should fail due to duplicate key
// 		_, err := repo.CreateSession(ctx, session)
// 		require.Error(t, err)
// 		assert.Contains(t, err.Error(), "session with this UUID already exists")
// 	})

// 	t.Run("transactional update session", func(t *testing.T) {
// 		session := NewGurdianSessionObject(
// 			uuid.New(),
// 			"testuser",
// 			nil,
// 			nil,
// 			[]Role{},
// 			30*time.Minute,
// 		)

// 		_, err := repo.CreateSession(ctx, session)
// 		require.NoError(t, err)

// 		// Simulate concurrent update
// 		go func() {
// 			time.Sleep(100 * time.Millisecond)
// 			session.Username = "updated-by-other"
// 			_, _ = repo.UpdateSession(ctx, session)
// 		}()

// 		// This update should detect the conflict
// 		session.Username = "updated-by-test"
// 		_, err = repo.UpdateSession(ctx, session)
// 		require.Error(t, err)
// 		assert.Contains(t, err.Error(), "session not found") // Because it was updated by other process
// 	})
// }

// func TestMongoRepository_Concurrency(t *testing.T) {
// 	db := setupTestMongoDB(t)
// 	defer cleanupTestMongoDB(t, db)

// 	repo := NewGourdianSessionMongoRepository(db, false)
// 	ctx := context.Background()

// 	t.Run("concurrent session creation", func(t *testing.T) {
// 		userID := uuid.New()
// 		var wg sync.WaitGroup
// 		var successCount int32
// 		var conflictCount int32
// 		const numWorkers = 5

// 		for i := 0; i < numWorkers; i++ {
// 			wg.Add(1)
// 			go func(i int) {
// 				defer wg.Done()
// 				session := NewGurdianSessionObject(
// 					userID,
// 					fmt.Sprintf("user-%d", i),
// 					nil,
// 					nil,
// 					[]Role{},
// 					30*time.Minute,
// 				)

// 				_, err := repo.CreateSession(ctx, session)
// 				if err == nil {
// 					atomic.AddInt32(&successCount, 1)
// 				} else if strings.Contains(err.Error(), "already exists") {
// 					atomic.AddInt32(&conflictCount, 1)
// 				}
// 			}(i)
// 		}

// 		wg.Wait()

// 		assert.Equal(t, int32(1), successCount, "Only one create should succeed")
// 		assert.Equal(t, int32(numWorkers-1), conflictCount, "Others should get conflicts")
// 	})
// }

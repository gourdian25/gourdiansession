package gourdiansession

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedisRepository_DeleteSession(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianRedisSessionRepository(client)
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

	repo := NewGurdianRedisSessionRepository(client)
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

	repo := NewGurdianRedisSessionRepository(client)
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

	repo := NewGurdianRedisSessionRepository(client)
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
		assert.Contains(t, err.Error(), "session expired")
	})
}

func TestRedisRepository_UpdateSession(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianRedisSessionRepository(client)
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

	repo := NewGurdianRedisSessionRepository(client)
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

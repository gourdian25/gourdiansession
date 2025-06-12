package gourdiansession

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

func setupTestRedis() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "GourdianRedisSecret",
		DB:       15,
	})
}

func cleanupTestRedis(t *testing.T, client *redis.Client) {
	ctx := context.Background()
	err := client.FlushDB(ctx).Err()
	assert.NoError(t, err)
}

func TestGourdianSessionIntegration(t *testing.T) {
	ctx := context.Background()
	redisClient := setupTestRedis()
	defer cleanupTestRedis(t, redisClient)

	// Test configuration
	config := &GourdianSessionConfig{
		MaxUserSessions:            5,
		MaxSessionsPerDevice:       2,
		MaxIPConnections:           3,
		AllowConcurrentSessions:    true,
		TrackIPAddresses:           true,
		TrackClientDevices:         true,
		DefaultSessionDuration:     30 * time.Minute,
		IdleTimeoutDuration:        15 * time.Minute,
		SessionRenewalWindow:       5 * time.Minute,
		AutoRevokeOnPasswordChange: true,
		BlockedUserAgents:          []string{"bot", "crawler"},
	}

	// Create service
	service := NewGourdianSession(redisClient, config)

	// Test data
	userID := uuid.New()
	username := "testuser"
	ipAddress := "192.168.1.1"
	userAgent := "test-agent"
	roles := []Role{
		{
			Name: "user",
			Permissions: []Permission{
				{
					Name:     "read",
					Resource: "profile",
					Action:   "read",
				},
			},
		},
	}

	t.Run("Create and Get Session", func(t *testing.T) {
		session, err := service.CreateSession(ctx, userID, username, &ipAddress, &userAgent, roles)
		assert.NoError(t, err)
		assert.NotNil(t, session)
		assert.Equal(t, userID, session.UserID)
		assert.Equal(t, username, session.Username)
		assert.Equal(t, SessionStatusActive, session.Status)
		assert.True(t, session.Authenticated)

		// Get the session
		retrieved, err := service.GetSession(ctx, session.UUID)
		assert.NoError(t, err)
		assert.Equal(t, session.UUID, retrieved.UUID)
	})

	t.Run("Validate Session", func(t *testing.T) {
		session, err := service.CreateSession(ctx, userID, username, &ipAddress, &userAgent, roles)
		assert.NoError(t, err)

		// Validate with just ID
		validSession, err := service.ValidateSession(ctx, session.UUID)
		assert.NoError(t, err)
		assert.Equal(t, session.UUID, validSession.UUID)

		// Validate with context
		validSession, err = service.ValidateSessionWithContext(ctx, session.UUID, ipAddress, userAgent)
		assert.NoError(t, err)
		assert.Equal(t, session.UUID, validSession.UUID)
	})

	t.Run("Session Quota Enforcement", func(t *testing.T) {
		// Create max sessions
		for i := 0; i < config.MaxUserSessions; i++ {
			_, err := service.CreateSession(ctx, userID, username, &ipAddress, &userAgent, roles)
			assert.NoError(t, err)
		}

		// Next one should fail
		_, err := service.CreateSession(ctx, userID, username, &ipAddress, &userAgent, roles)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "maximum number of sessions reached")
	})

	t.Run("Revoke Sessions", func(t *testing.T) {
		session1, _ := service.CreateSession(ctx, userID, username, &ipAddress, &userAgent, roles)
		session2, _ := service.CreateSession(ctx, userID, username, &ipAddress, &userAgent, roles)

		// Revoke one session
		err := service.RevokeSession(ctx, session1.UUID)
		assert.NoError(t, err)

		// Verify revoked session is invalid
		_, err = service.ValidateSession(ctx, session1.UUID)
		assert.Error(t, err)

		// Other session should still be valid
		_, err = service.ValidateSession(ctx, session2.UUID)
		assert.NoError(t, err)

		// Revoke all sessions
		err = service.RevokeAllUserSessions(ctx, userID)
		assert.NoError(t, err)

		// Verify all sessions are revoked
		_, err = service.ValidateSession(ctx, session2.UUID)
		assert.Error(t, err)
	})

	t.Run("Session Data Operations", func(t *testing.T) {
		session, _ := service.CreateSession(ctx, userID, username, &ipAddress, &userAgent, roles)

		// Set data
		err := service.SetSessionData(ctx, session.UUID, "test-key", "test-value")
		assert.NoError(t, err)

		// Get data
		value, err := service.GetSessionData(ctx, session.UUID, "test-key")
		assert.NoError(t, err)
		assert.Equal(t, "test-value", value)

		// Delete data
		err = service.DeleteSessionData(ctx, session.UUID, "test-key")
		assert.NoError(t, err)

		// Verify deleted
		_, err = service.GetSessionData(ctx, session.UUID, "test-key")
		assert.Error(t, err)
	})

	t.Run("Temporary Data Operations", func(t *testing.T) {
		// Set temp data
		err := service.SetTemporaryData(ctx, "temp-key", "temp-value", 1*time.Minute)
		assert.NoError(t, err)

		// Get temp data
		value, err := service.GetTemporaryData(ctx, "temp-key")
		assert.NoError(t, err)
		assert.Equal(t, "temp-value", value)

		// Delete temp data
		err = service.DeleteTemporaryData(ctx, "temp-key")
		assert.NoError(t, err)

		// Verify deleted
		_, err = service.GetTemporaryData(ctx, "temp-key")
		assert.Error(t, err)
	})

	t.Run("Session Refresh", func(t *testing.T) {
		// Create session with short duration
		shortConfig := *config
		shortConfig.DefaultSessionDuration = 2 * time.Second
		shortConfig.SessionRenewalWindow = 1 * time.Second
		shortService := NewGourdianSession(redisClient, &shortConfig)

		session, err := shortService.CreateSession(ctx, userID, username, &ipAddress, &userAgent, roles)
		assert.NoError(t, err)

		originalExpiry := session.ExpiresAt

		// Wait until within renewal window
		time.Sleep(1500 * time.Millisecond)

		// Refresh session
		refreshed, err := shortService.RefreshSession(ctx, session.UUID)
		assert.NoError(t, err)
		assert.True(t, refreshed.ExpiresAt.After(originalExpiry))
	})

	t.Run("Blocked User Agent", func(t *testing.T) {
		blockedUA := "some-bot-user-agent"
		_, err := service.CreateSession(ctx, userID, username, &ipAddress, &blockedUA, roles)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user agent is blocked")
	})
}

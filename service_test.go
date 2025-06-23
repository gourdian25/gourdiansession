// service_test.go
package gourdiansession

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionService_SessionDataOperations(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianRedisSessionRepository(client)
	svc := NewGourdianSessionService(repo, testConfig())
	ctx := context.Background()

	session, _ := createTestSession(t, svc)

	t.Run("set and get session data", func(t *testing.T) {
		err := svc.SetSessionData(ctx, session.UUID, "testkey", "testvalue")
		require.NoError(t, err)

		val, err := svc.GetSessionData(ctx, session.UUID, "testkey")
		require.NoError(t, err)
		assert.Equal(t, "testvalue", val)
	})

	t.Run("delete session data", func(t *testing.T) {
		err := svc.SetSessionData(ctx, session.UUID, "todelete", "value")
		require.NoError(t, err)

		err = svc.DeleteSessionData(ctx, session.UUID, "todelete")
		require.NoError(t, err)

		_, err = svc.GetSessionData(ctx, session.UUID, "todelete")
		require.Error(t, err)
	})

	t.Run("get from invalid session", func(t *testing.T) {
		_, err := svc.GetSessionData(ctx, uuid.New(), "anykey")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session validation failed")
	})
}

func TestSessionService_TemporaryDataOperations(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianRedisSessionRepository(client)
	svc := NewGourdianSessionService(repo, testConfig())
	ctx := context.Background()

	t.Run("set and get temporary data", func(t *testing.T) {
		err := svc.SetTemporaryData(ctx, "tempkey", "tempvalue", 1*time.Minute)
		require.NoError(t, err)

		val, err := svc.GetTemporaryData(ctx, "tempkey")
		require.NoError(t, err)
		assert.Equal(t, "tempvalue", val)
	})

	t.Run("temporary data expiration", func(t *testing.T) {
		err := svc.SetTemporaryData(ctx, "shortlive", "value", 1*time.Millisecond)
		require.NoError(t, err)

		time.Sleep(2 * time.Millisecond)

		_, err = svc.GetTemporaryData(ctx, "shortlive")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "temporary data not found")
	})

	t.Run("delete temporary data", func(t *testing.T) {
		err := svc.SetTemporaryData(ctx, "todelete", "value", 1*time.Minute)
		require.NoError(t, err)

		err = svc.DeleteTemporaryData(ctx, "todelete")
		require.NoError(t, err)

		_, err = svc.GetTemporaryData(ctx, "todelete")
		require.Error(t, err)
	})
}

func TestSessionService_CreateSession(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	// Create a modified config for testing
	testCfg := &GourdianSessionConfig{
		MaxUserSessions:         3, // Set a low limit for testing
		MaxSessionsPerDevice:    2, // Should be lower than MaxUserSessions for this test
		AllowConcurrentSessions: true,
		TrackClientDevices:      true, // This was missing
		DefaultSessionDuration:  30 * time.Minute,
		BlockedUserAgents:       []string{"badbot"},
	}

	repo := NewGurdianRedisSessionRepository(client)
	svc := NewGourdianSessionService(repo, testCfg)
	ctx := context.Background()

	// ... other test cases ...

	t.Run("max sessions per user", func(t *testing.T) {
		userID := uuid.New()
		username := "testuser"
		ip := "192.168.1.1"
		ua := "test-agent"
		roles := []Role{}

		// Create max allowed sessions
		for i := 0; i < testCfg.MaxUserSessions; i++ {
			// Use different user agents to avoid hitting device limit
			uniqueUA := fmt.Sprintf("%s-%d", ua, i)
			_, err := svc.CreateSession(ctx, userID, username, &ip, &uniqueUA, roles)
			require.NoError(t, err)
		}

		// Next one should fail with user session limit
		_, err := svc.CreateSession(ctx, userID, username, &ip, &ua, roles)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "maximum number of sessions reached for user")
	})

	t.Run("max sessions per device", func(t *testing.T) {
		userID := uuid.New()
		username := "testuser"
		ip := "192.168.1.1"
		ua := "test-agent" // Same UA for all sessions
		roles := []Role{}

		// Create max allowed device sessions (but stay under user session limit)
		for i := 0; i < testCfg.MaxSessionsPerDevice; i++ {
			_, err := svc.CreateSession(ctx, userID, username, &ip, &ua, roles)
			require.NoError(t, err)
		}

		// Next one should fail with device limit (even though we're under user session limit)
		_, err := svc.CreateSession(ctx, userID, username, &ip, &ua, roles)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "maximum number of sessions reached for this device")
	})
}

// func TestSessionService_ValidateSession(t *testing.T) {
// 	client := setupTestRedis()
// 	defer cleanupTestRedis(t, client)

// 	repo := NewGurdianRedisSessionRepository(client)
// 	svc := NewGourdianSessionService(repo, testConfig())
// 	ctx := context.Background()

// 	t.Run("valid session", func(t *testing.T) {
// 		session, _ := createTestSession(t, svc)

// 		validated, err := svc.ValidateSession(ctx, session.UUID)
// 		require.NoError(t, err)
// 		assert.Equal(t, session.UUID, validated.UUID)
// 	})

// 	t.Run("invalid session ID", func(t *testing.T) {
// 		_, err := svc.ValidateSession(ctx, uuid.Nil)
// 		require.Error(t, err)
// 		assert.Contains(t, err.Error(), "session ID cannot be empty")
// 	})

// 	t.Run("expired session", func(t *testing.T) {
// 		// Create a custom config with very short session duration
// 		cfg := testConfig()
// 		cfg.DefaultSessionDuration = 1 * time.Millisecond
// 		svc := NewGourdianSessionService(repo, cfg)

// 		session, _ := createTestSession(t, svc)

// 		// Wait for session to expire
// 		time.Sleep(2 * time.Millisecond)

// 		_, err := svc.ValidateSession(ctx, session.UUID)
// 		require.Error(t, err)
// 		assert.Contains(t, err.Error(), "session has expired")
// 	})

// 	t.Run("idle timeout", func(t *testing.T) {
// 		// Create a custom config with very short idle timeout
// 		cfg := testConfig()
// 		cfg.IdleTimeoutDuration = 1 * time.Millisecond
// 		svc := NewGourdianSessionService(repo, cfg)

// 		session, _ := createTestSession(t, svc)

// 		// Wait for idle timeout
// 		time.Sleep(2 * time.Millisecond)

// 		_, err := svc.ValidateSession(ctx, session.UUID)
// 		require.Error(t, err)
// 		assert.Contains(t, err.Error(), "session expired due to inactivity")
// 	})
// }

// func TestSessionService_RefreshSession(t *testing.T) {
// 	client := setupTestRedis()
// 	defer cleanupTestRedis(t, client)

// 	repo := NewGurdianRedisSessionRepository(client)
// 	ctx := context.Background()

// 	t.Run("refresh within renewal window", func(t *testing.T) {
// 		// Create a custom config with specific renewal window
// 		cfg := testConfig()
// 		cfg.DefaultSessionDuration = 1 * time.Hour
// 		cfg.SessionRenewalWindow = 30 * time.Minute
// 		svc := NewGourdianSessionService(repo, cfg)

// 		session, _ := createTestSession(t, svc)
// 		originalExpiry := session.ExpiresAt

// 		// Set last activity to put us within renewal window
// 		newActivity := time.Now().Add(-25 * time.Minute)
// 		session.LastActivity = newActivity
// 		_, err := repo.UpdateSession(ctx, session)
// 		require.NoError(t, err)

// 		refreshed, err := svc.RefreshSession(ctx, session.UUID)
// 		require.NoError(t, err)
// 		assert.True(t, refreshed.ExpiresAt.After(originalExpiry))
// 	})

// 	t.Run("refresh outside renewal window", func(t *testing.T) {
// 		// Create a custom config with specific renewal window
// 		cfg := testConfig()
// 		cfg.DefaultSessionDuration = 1 * time.Hour
// 		cfg.SessionRenewalWindow = 10 * time.Minute
// 		svc := NewGourdianSessionService(repo, cfg)

// 		session, _ := createTestSession(t, svc)
// 		originalExpiry := session.ExpiresAt

// 		// Set last activity to be outside renewal window
// 		newActivity := time.Now().Add(-5 * time.Minute)
// 		session.LastActivity = newActivity
// 		_, err := repo.UpdateSession(ctx, session)
// 		require.NoError(t, err)

// 		refreshed, err := svc.RefreshSession(ctx, session.UUID)
// 		require.NoError(t, err)
// 		assert.Equal(t, originalExpiry, refreshed.ExpiresAt)
// 	})
// }

// func TestSessionService_RevokeOperations(t *testing.T) {
// 	client := setupTestRedis()
// 	defer cleanupTestRedis(t, client)

// 	repo := NewGurdianRedisSessionRepository(client)
// 	svc := NewGourdianSessionService(repo, testConfig())
// 	ctx := context.Background()

// 	t.Run("revoke single session", func(t *testing.T) {
// 		session, _ := createTestSession(t, svc)

// 		err := svc.RevokeSession(ctx, session.UUID)
// 		require.NoError(t, err)

// 		validated, err := svc.ValidateSession(ctx, session.UUID)
// 		require.Error(t, err)
// 		assert.Nil(t, validated)
// 		assert.Contains(t, err.Error(), "session is not active")
// 	})

// 	t.Run("revoke all user sessions", func(t *testing.T) {
// 		_, userID := createTestSession(t, svc)

// 		// Create multiple sessions for the user
// 		for i := 0; i < 3; i++ {
// 			_, err := svc.CreateSession(ctx, userID, "testuser", strPtr("192.168.1.1"), strPtr("test-agent"), []Role{})
// 			require.NoError(t, err)
// 		}

// 		activeBefore, err := svc.GetActiveUserSessions(ctx, userID)
// 		require.NoError(t, err)
// 		assert.True(t, len(activeBefore) > 0)

// 		err = svc.RevokeAllUserSessions(ctx, userID)
// 		require.NoError(t, err)

// 		activeAfter, err := svc.GetActiveUserSessions(ctx, userID)
// 		require.NoError(t, err)
// 		assert.Equal(t, 0, len(activeAfter))
// 	})

// 	t.Run("revoke other user sessions", func(t *testing.T) {
// 		session1, userID := createTestSession(t, svc)
// 		session2, err := svc.CreateSession(ctx, userID, "testuser", strPtr("192.168.1.1"), strPtr("test-agent"), []Role{})
// 		require.NoError(t, err)

// 		// Revoke all except session1
// 		err = svc.RevokeOtherUserSessions(ctx, userID, session1.UUID)
// 		require.NoError(t, err)

// 		// session1 should still be active
// 		valid1, err := svc.ValidateSession(ctx, session1.UUID)
// 		require.NoError(t, err)
// 		assert.NotNil(t, valid1)

// 		// session2 should be revoked
// 		valid2, err := svc.ValidateSession(ctx, session2.UUID)
// 		require.Error(t, err)
// 		assert.Nil(t, valid2)
// 	})
// }

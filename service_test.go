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

	repo := NewGurdianSessionRedisRepository(client)
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

	repo := NewGurdianSessionRedisRepository(client)
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

	repo := NewGurdianSessionRedisRepository(client)
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

func TestSessionService_ValidateSession(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	testCfg := testConfig()
	repo := NewGurdianSessionRedisRepository(client)
	svc := NewGourdianSessionService(repo, testCfg)
	ctx := context.Background()

	t.Run("valid session", func(t *testing.T) {
		session, _ := createTestSession(t, svc)

		validated, err := svc.ValidateSession(ctx, session.UUID)
		require.NoError(t, err)
		assert.Equal(t, session.UUID, validated.UUID)
	})

	t.Run("invalid session ID", func(t *testing.T) {
		_, err := svc.ValidateSession(ctx, uuid.Nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session ID cannot be empty")
	})

	t.Run("expired session", func(t *testing.T) {
		// Create a session with very short expiration
		session, _ := createTestSession(t, svc)

		// Manually set expiration to past
		session.ExpiresAt = time.Now().Add(-1 * time.Second)
		_, err := repo.UpdateSession(ctx, session)
		require.NoError(t, err)

		// Wait a bit to ensure expiration
		time.Sleep(10 * time.Millisecond)

		// Validate should return expired error
		_, err = svc.ValidateSession(ctx, session.UUID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session has expired")
	})

	t.Run("idle timeout", func(t *testing.T) {
		// Create a custom config with very short idle timeout
		cfg := testConfig()
		cfg.IdleTimeoutDuration = 1 * time.Millisecond
		svc := NewGourdianSessionService(repo, cfg)

		session, _ := createTestSession(t, svc)

		// Wait for idle timeout
		time.Sleep(2 * time.Millisecond)

		_, err := svc.ValidateSession(ctx, session.UUID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session expired due to inactivity")
	})
}

func TestSessionService_RefreshSession(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	ctx := context.Background()

	t.Run("refresh within renewal window", func(t *testing.T) {
		// Create a custom config
		cfg := testConfig()
		cfg.DefaultSessionDuration = 1 * time.Hour
		cfg.SessionRenewalWindow = 30 * time.Minute
		cfg.IdleTimeoutDuration = 0 // Disable idle timeout
		svc := NewGourdianSessionService(repo, cfg)

		// Set up test time points
		now := time.Now()
		originalExpiry := now.Add(25 * time.Minute) // Session has 25 minutes remaining (within 30m window)

		// Create test session
		session, _ := createTestSession(t, svc)
		session.CreatedAt = now.Add(-35 * time.Minute)
		session.LastActivity = now.Add(-5 * time.Minute)
		session.ExpiresAt = originalExpiry
		_, err := repo.UpdateSession(ctx, session)
		require.NoError(t, err)

		// Should extend since we're within renewal window (25m < 30m)
		refreshed, err := svc.RefreshSession(ctx, session.UUID)
		require.NoError(t, err)

		// New expiry should be now + 1 hour
		expectedExpiry := now.Add(cfg.DefaultSessionDuration)
		assert.True(t, refreshed.ExpiresAt.After(originalExpiry),
			"Expiry time should have been extended")
		assert.WithinDuration(t, expectedExpiry, refreshed.ExpiresAt, time.Second,
			"New expiry should be now + default duration")
	})

	t.Run("refresh outside renewal window", func(t *testing.T) {
		// Create a custom config with specific renewal window and disabled idle timeout
		cfg := testConfig()
		cfg.DefaultSessionDuration = 1 * time.Hour
		cfg.SessionRenewalWindow = 10 * time.Minute
		cfg.IdleTimeoutDuration = 0 // Disable idle timeout for this test
		svc := NewGourdianSessionService(repo, cfg)

		session, _ := createTestSession(t, svc)
		originalExpiry := session.ExpiresAt.UTC() // Ensure UTC for comparison

		// Set last activity to be outside renewal window but recent enough
		newActivity := time.Now().Add(-5 * time.Minute)
		session.LastActivity = newActivity
		_, err := repo.UpdateSession(ctx, session)
		require.NoError(t, err)

		refreshed, err := svc.RefreshSession(ctx, session.UUID)
		require.NoError(t, err)
		assert.Equal(t, originalExpiry, refreshed.ExpiresAt.UTC()) // Compare UTC times
	})
}

func TestSessionService_RevokeOperations(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	// Create test config with relaxed limits for testing revocation
	testCfg := testConfig()
	testCfg.MaxSessionsPerDevice = 10 // Increase device limit for testing
	testCfg.MaxUserSessions = 10      // Increase user limit for testing

	repo := NewGurdianSessionRedisRepository(client)
	svc := NewGourdianSessionService(repo, testCfg)
	ctx := context.Background()

	t.Run("revoke single session", func(t *testing.T) {
		session, _ := createTestSession(t, svc)

		err := svc.RevokeSession(ctx, session.UUID)
		require.NoError(t, err)

		validated, err := svc.ValidateSession(ctx, session.UUID)
		require.Error(t, err)
		assert.Nil(t, validated)
		assert.Contains(t, err.Error(), "session is not active")
	})

	t.Run("revoke all user sessions", func(t *testing.T) {
		userID := uuid.New()

		// Create multiple sessions with different user agents to avoid device limits
		for i := 0; i < 3; i++ {
			ua := fmt.Sprintf("test-agent-%d", i)
			_, err := svc.CreateSession(ctx, userID, "testuser", strPtr("192.168.1.1"), &ua, []Role{})
			require.NoError(t, err)
		}

		activeBefore, err := svc.GetActiveUserSessions(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, 3, len(activeBefore), "Should have 3 active sessions before revocation")

		err = svc.RevokeAllUserSessions(ctx, userID)
		require.NoError(t, err)

		activeAfter, err := svc.GetActiveUserSessions(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, 0, len(activeAfter), "All sessions should be revoked")
	})

	t.Run("revoke other user sessions", func(t *testing.T) {
		userID := uuid.New()

		// Create sessions with different user agents
		session1, err := svc.CreateSession(ctx, userID, "testuser", strPtr("192.168.1.1"), strPtr("test-agent-1"), []Role{})
		require.NoError(t, err)

		session2, err := svc.CreateSession(ctx, userID, "testuser", strPtr("192.168.1.1"), strPtr("test-agent-2"), []Role{})
		require.NoError(t, err)

		// Revoke all except session1
		err = svc.RevokeOtherUserSessions(ctx, userID, session1.UUID)
		require.NoError(t, err)

		// session1 should still be active
		valid1, err := svc.ValidateSession(ctx, session1.UUID)
		require.NoError(t, err)
		assert.NotNil(t, valid1)

		// session2 should be revoked
		valid2, err := svc.ValidateSession(ctx, session2.UUID)
		require.Error(t, err)
		assert.Nil(t, valid2)
	})
}

// Add these tests to your service_test.go file

func TestNewGourdianSession(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	config := testConfig()
	service := NewGourdianRedisSession(client, config)

	assert.NotNil(t, service)
}

func TestSessionService_GetSession(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	svc := NewGourdianSessionService(repo, testConfig())
	ctx := context.Background()

	t.Run("get existing session", func(t *testing.T) {
		session, _ := createTestSession(t, svc)

		retrieved, err := svc.GetSession(ctx, session.UUID)
		require.NoError(t, err)
		assert.Equal(t, session.UUID, retrieved.UUID)
	})

	t.Run("get non-existent session", func(t *testing.T) {
		_, err := svc.GetSession(ctx, uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get session")
	})

	t.Run("get with nil session ID", func(t *testing.T) {
		_, err := svc.GetSession(ctx, uuid.Nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session ID cannot be empty")
	})
}

func TestSessionService_UpdateSessionActivity(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	svc := NewGourdianSessionService(repo, testConfig())
	ctx := context.Background()

	t.Run("update activity", func(t *testing.T) {
		session, _ := createTestSession(t, svc)
		originalActivity := session.LastActivity

		time.Sleep(10 * time.Millisecond) // Ensure time passes
		err := svc.UpdateSessionActivity(ctx, session.UUID)
		require.NoError(t, err)

		updated, err := svc.GetSession(ctx, session.UUID)
		require.NoError(t, err)
		assert.True(t, updated.LastActivity.After(originalActivity))
	})

	t.Run("update non-existent session", func(t *testing.T) {
		err := svc.UpdateSessionActivity(ctx, uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to update session activity")
	})
}

func TestSessionService_ExtendSession(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	svc := NewGourdianSessionService(repo, testConfig())
	ctx := context.Background()

	t.Run("extend valid session", func(t *testing.T) {
		session, _ := createTestSession(t, svc)
		originalExpiry := session.ExpiresAt

		extended, err := svc.ExtendSession(ctx, session.UUID, 1*time.Hour)
		require.NoError(t, err)
		assert.True(t, extended.ExpiresAt.After(originalExpiry))
	})

	t.Run("extend with invalid duration", func(t *testing.T) {
		session, _ := createTestSession(t, svc)
		_, err := svc.ExtendSession(ctx, session.UUID, -1*time.Hour)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duration must be positive")
	})

	t.Run("extend revoked session", func(t *testing.T) {
		session, _ := createTestSession(t, svc)
		err := svc.RevokeSession(ctx, session.UUID)
		require.NoError(t, err)

		_, err = svc.ExtendSession(ctx, session.UUID, 1*time.Hour)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session validation failed")
	})
}

func TestSessionService_ValidateSessionWithContext(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	svc := NewGourdianSessionService(repo, testConfig())
	ctx := context.Background()

	ip := "192.168.1.1"
	ua := "test-agent"

	t.Run("validate with matching context", func(t *testing.T) {
		session, _ := createTestSession(t, svc)
		session.IPAddress = &ip
		session.UserAgent = &ua
		_, err := repo.UpdateSession(ctx, session)
		require.NoError(t, err)

		validated, err := svc.ValidateSessionWithContext(ctx, session.UUID, ip, ua)
		require.NoError(t, err)
		assert.Equal(t, session.UUID, validated.UUID)
	})

	t.Run("validate with IP mismatch", func(t *testing.T) {
		session, _ := createTestSession(t, svc)
		session.IPAddress = &ip
		session.UserAgent = &ua
		_, err := repo.UpdateSession(ctx, session)
		require.NoError(t, err)

		_, err = svc.ValidateSessionWithContext(ctx, session.UUID, "10.0.0.1", ua)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "IP address mismatch")
	})

	t.Run("validate with UA mismatch", func(t *testing.T) {
		session, _ := createTestSession(t, svc)
		session.IPAddress = &ip
		session.UserAgent = &ua
		_, err := repo.UpdateSession(ctx, session)
		require.NoError(t, err)

		_, err = svc.ValidateSessionWithContext(ctx, session.UUID, ip, "different-agent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user agent mismatch")
	})

	t.Run("validate with empty inputs", func(t *testing.T) {
		_, err := svc.ValidateSessionWithContext(ctx, uuid.Nil, "", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session ID cannot be empty")
	})
}

func TestSessionService_GetUserSessions(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianSessionRedisRepository(client)
	svc := NewGourdianSessionService(repo, testConfig())
	ctx := context.Background()

	t.Run("get sessions for user with none", func(t *testing.T) {
		sessions, err := svc.GetUserSessions(ctx, uuid.New())
		require.NoError(t, err)
		assert.Empty(t, sessions)
	})

	t.Run("get sessions for user with multiple", func(t *testing.T) {
		// Create first session
		session1, err := svc.CreateSession(ctx, uuid.New(), "user1", nil, nil, []Role{})
		require.NoError(t, err)
		userID := session1.UserID

		// Create second session with same user ID
		session2, err := svc.CreateSession(ctx, userID, "user1", nil, nil, []Role{})
		require.NoError(t, err)

		sessions, err := svc.GetUserSessions(ctx, userID)
		require.NoError(t, err)
		assert.Len(t, sessions, 2)

		// Verify both sessions are present
		var foundSession1, foundSession2 bool
		for _, s := range sessions {
			if s.UUID == session1.UUID {
				foundSession1 = true
			}
			if s.UUID == session2.UUID {
				foundSession2 = true
			}
		}
		assert.True(t, foundSession1, "session1 not found in results")
		assert.True(t, foundSession2, "session2 not found in results")
	})

	t.Run("get with nil user ID", func(t *testing.T) {
		_, err := svc.GetUserSessions(ctx, uuid.Nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user ID cannot be empty")
	})
}

func TestSessionService_EnforceSessionLimits(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	// Create a config that specifically tests single session enforcement
	singleSessionConfig := &GourdianSessionConfig{
		MaxUserSessions:         5,     // Set high enough not to trigger
		MaxSessionsPerDevice:    5,     // Set high enough not to trigger
		MaxIPConnections:        5,     // Set high enough not to trigger
		AllowConcurrentSessions: false, // This is what we're testing
		TrackIPAddresses:        true,
		TrackClientDevices:      true,
		DefaultSessionDuration:  30 * time.Minute,
	}

	repo := NewGurdianSessionRedisRepository(client)
	svc := NewGourdianSessionService(repo, singleSessionConfig)
	ctx := context.Background()

	userID := uuid.New()
	ip := "192.168.1.1"
	ua := "test-agent"

	t.Run("enforce single session", func(t *testing.T) {
		// Create first session
		sess1, err := svc.CreateSession(ctx, userID, "testuser", &ip, &ua, []Role{})
		require.NoError(t, err)

		// Try to create another session - should work but revoke the first one
		_, err = svc.CreateSession(ctx, userID, "testuser", &ip, &ua, []Role{})
		require.NoError(t, err)

		// Verify first session was revoked
		updatedSess1, err := svc.GetSession(ctx, sess1.UUID)
		if assert.NoError(t, err) {
			assert.Equal(t, SessionStatusRevoked, updatedSess1.Status)
		} else {
			// If we get "not found", that's also acceptable since the session might have been cleaned up
			assert.ErrorIs(t, err, ErrNotFound)
		}
	})

	t.Run("enforce with nil IP and UA", func(t *testing.T) {
		// Should work with nil IP/UA when not tracking them
		looseConfig := &GourdianSessionConfig{
			TrackIPAddresses:        false,
			TrackClientDevices:      false,
			AllowConcurrentSessions: false,
		}
		looseSvc := NewGourdianSessionService(repo, looseConfig)

		err := looseSvc.EnforceSessionLimits(ctx, userID, nil, nil)
		require.NoError(t, err)
	})
}

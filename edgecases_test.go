// edgecases_test.go
package gourdiansession

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEdgeCases(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianRedisSessionRepository(client)
	svc := NewGourdianSessionService(repo, testConfig())
	ctx := context.Background()

	t.Run("session with nil IP and UA", func(t *testing.T) {
		userID := uuid.New()
		username := "testuser"
		roles := []Role{}

		session, err := svc.CreateSession(ctx, userID, username, nil, nil, roles)
		require.NoError(t, err)
		assert.Nil(t, session.IPAddress)
		assert.Nil(t, session.UserAgent)
	})

	t.Run("validate with mismatched IP/UA", func(t *testing.T) {
		session, _ := createTestSession(t, svc)

		// Should fail with wrong IP
		_, err := svc.ValidateSessionWithContext(ctx, session.UUID, "10.0.0.1", *session.UserAgent)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "IP address mismatch")

		// Should fail with wrong UA
		_, err = svc.ValidateSessionWithContext(ctx, session.UUID, *session.IPAddress, "wrong-agent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user agent mismatch")
	})

	t.Run("session with empty roles", func(t *testing.T) {
		userID := uuid.New()
		username := "testuser"
		ip := "192.168.1.1"
		ua := "test-agent"

		session, err := svc.CreateSession(ctx, userID, username, &ip, &ua, nil)
		require.NoError(t, err)
		assert.Equal(t, 0, len(session.Roles))
	})

	t.Run("session with complex data types", func(t *testing.T) {
		session, _ := createTestSession(t, svc)

		complexData := map[string]interface{}{
			"nested": map[string]interface{}{
				"value": 42,
				"list":  []string{"a", "b", "c"},
			},
			"timestamp": time.Now(),
		}

		err := svc.SetSessionData(ctx, session.UUID, "complex", complexData)
		require.NoError(t, err)

		retrieved, err := svc.GetSessionData(ctx, session.UUID, "complex")
		require.NoError(t, err)
		assert.IsType(t, map[string]interface{}{}, retrieved)
	})
}

func TestSessionService_ErrorHandling(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianRedisSessionRepository(client)
	svc := NewGourdianSessionService(repo, testConfig())
	ctx := context.Background()

	t.Run("validate non-existent session", func(t *testing.T) {
		_, err := svc.ValidateSession(ctx, uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session validation failed")
	})

	t.Run("validate nil session ID", func(t *testing.T) {
		_, err := svc.ValidateSession(ctx, uuid.Nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session ID cannot be empty")
	})

	t.Run("get session data from revoked session", func(t *testing.T) {
		session, _ := createTestSession(t, svc)
		err := svc.RevokeSession(ctx, session.UUID)
		require.NoError(t, err)

		_, err = svc.GetSessionData(ctx, session.UUID, "anykey")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session validation failed")
	})

	t.Run("set session data in expired session", func(t *testing.T) {
		// Create a session with very short expiration
		cfg := testConfig()
		cfg.DefaultSessionDuration = 1 * time.Millisecond
		svc := NewGourdianSessionService(repo, cfg)

		session, _ := createTestSession(t, svc)
		time.Sleep(10 * time.Millisecond)

		err := svc.SetSessionData(ctx, session.UUID, "testkey", "value")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session validation failed")
	})
}

func TestSessionService_ConfigurationEdgeCases(t *testing.T) {
	client := setupTestRedis()
	defer cleanupTestRedis(t, client)

	repo := NewGurdianRedisSessionRepository(client)
	ctx := context.Background()

	t.Run("zero max sessions", func(t *testing.T) {
		cfg := testConfig()
		cfg.MaxUserSessions = 0 // Unlimited
		svc := NewGourdianSessionService(repo, cfg)

		userID := uuid.New()
		for i := 0; i < 10; i++ { // Create many sessions
			_, err := svc.CreateSession(ctx, userID, "testuser", nil, nil, []Role{})
			require.NoError(t, err)
		}

		sessions, err := svc.GetActiveUserSessions(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, 10, len(sessions))
	})

	t.Run("disabled IP tracking", func(t *testing.T) {
		cfg := testConfig()
		cfg.TrackIPAddresses = false
		svc := NewGourdianSessionService(repo, cfg)

		userID := uuid.New()
		ip := "192.168.1.1"

		// Create multiple sessions with same IP (shouldn't trigger limit)
		for i := 0; i < 5; i++ {
			_, err := svc.CreateSession(ctx, userID, "testuser", &ip, nil, []Role{})
			require.NoError(t, err)
		}
	})

	t.Run("disabled device tracking", func(t *testing.T) {
		cfg := testConfig()
		cfg.TrackClientDevices = false
		svc := NewGourdianSessionService(repo, cfg)

		userID := uuid.New()
		ua := "test-agent"

		// Create multiple sessions with same UA (shouldn't trigger limit)
		for i := 0; i < 5; i++ {
			_, err := svc.CreateSession(ctx, userID, "testuser", nil, &ua, []Role{})
			require.NoError(t, err)
		}
	})

	t.Run("negative idle timeout", func(t *testing.T) {
		cfg := testConfig()
		cfg.IdleTimeoutDuration = -1 * time.Minute // Disabled
		svc := NewGourdianSessionService(repo, cfg)

		session, _ := createTestSession(t, svc)
		time.Sleep(100 * time.Millisecond)

		// Should still validate since idle timeout is disabled
		_, err := svc.ValidateSession(ctx, session.UUID)
		require.NoError(t, err)
	})
}

// func TestRedisRepository_ValidateSessionByID_EdgeCases(t *testing.T) {
// 	client := setupTestRedis()
// 	defer cleanupTestRedis(t, client)

// 	repo := NewGurdianRedisSessionRepository(client)
// 	ctx := context.Background()

// 	t.Run("expired session marking", func(t *testing.T) {
// 		session := NewGurdianSessionObject(
// 			uuid.New(),
// 			"testuser",
// 			nil,
// 			nil,
// 			[]Role{},
// 			1*time.Millisecond, // Very short expiration
// 		)

// 		_, err := repo.CreateSession(ctx, session)
// 		require.NoError(t, err)

// 		// Wait for expiration
// 		time.Sleep(10 * time.Millisecond)

// 		_, err = repo.ValidateSessionByID(ctx, session.UUID)
// 		require.Error(t, err)
// 		assert.Contains(t, err.Error(), "session has expired")

// 		// Verify session was marked as expired
// 		stored, err := repo.GetSessionByID(ctx, session.UUID)
// 		require.NoError(t, err)
// 		assert.Equal(t, SessionStatusExpired, stored.Status)
// 	})

// 	t.Run("failed status update on expiration", func(t *testing.T) {
// 		// Create a session that will expire
// 		session := NewGurdianSessionObject(
// 			uuid.New(),
// 			"testuser",
// 			nil,
// 			nil,
// 			[]Role{},
// 			1*time.Millisecond,
// 		)

// 		_, err := repo.CreateSession(ctx, session)
// 		require.NoError(t, err)

// 		// Wait for expiration
// 		time.Sleep(10 * time.Millisecond)

// 		// Delete the session to force update failure
// 		err = repo.DeleteSession(ctx, session.UUID)
// 		require.NoError(t, err)

// 		// Validation should still fail with expired error
// 		_, err = repo.ValidateSessionByID(ctx, session.UUID)
// 		require.Error(t, err)
// 		assert.Contains(t, err.Error(), "session not found")
// 	})

// 	t.Run("session with zero expiration time", func(t *testing.T) {
// 		session := NewGurdianSessionObject(
// 			uuid.New(),
// 			"testuser",
// 			nil,
// 			nil,
// 			[]Role{},
// 			0, // Zero expiration
// 		)

// 		_, err := repo.CreateSession(ctx, session)
// 		require.NoError(t, err)

// 		// Should be treated as already expired
// 		_, err = repo.ValidateSessionByID(ctx, session.UUID)
// 		require.Error(t, err)
// 		assert.Contains(t, err.Error(), "session has expired")
// 	})
// }

// func TestSessionService_EdgeCases(t *testing.T) {
// 	client := setupTestRedis()
// 	defer cleanupTestRedis(t, client)

// 	repo := NewGurdianRedisSessionRepository(client)
// 	svc := NewGourdianSessionService(repo, testConfig())
// 	ctx := context.Background()

// 	t.Run("create session with blocked user agent", func(t *testing.T) {
// 		userID := uuid.New()
// 		username := "testuser"
// 		ip := "192.168.1.1"
// 		ua := "badbot-scraper" // Contains "badbot" which is in blocked list
// 		roles := []Role{}

// 		_, err := svc.CreateSession(ctx, userID, username, &ip, &ua, roles)
// 		require.Error(t, err)
// 		assert.Contains(t, err.Error(), "user agent is blocked")
// 	})

// 	t.Run("session quota with nil IP and UA", func(t *testing.T) {
// 		userID := uuid.New()

// 		// Should work when not tracking IP/UA
// 		cfg := testConfig()
// 		cfg.TrackIPAddresses = false
// 		cfg.TrackClientDevices = false
// 		svc := NewGourdianSessionService(repo, cfg)

// 		err := svc.CheckSessionQuota(ctx, userID, nil, nil)
// 		require.NoError(t, err)
// 	})

// 	t.Run("refresh session with negative renewal window", func(t *testing.T) {
// 		cfg := testConfig()
// 		cfg.SessionRenewalWindow = -1 * time.Minute // Negative window
// 		svc := NewGourdianSessionService(repo, cfg)

// 		session, _ := createTestSession(t, svc)

// 		// Should not extend since renewal window is negative
// 		refreshed, err := svc.RefreshSession(ctx, session.UUID)
// 		require.NoError(t, err)
// 		assert.Equal(t, session.ExpiresAt, refreshed.ExpiresAt)
// 	})

// 	t.Run("extend session with zero duration", func(t *testing.T) {
// 		session, _ := createTestSession(t, svc)

// 		_, err := svc.ExtendSession(ctx, session.UUID, 0)
// 		require.Error(t, err)
// 		assert.Contains(t, err.Error(), "duration must be positive")
// 	})

// 	t.Run("session data with empty key", func(t *testing.T) {
// 		session, _ := createTestSession(t, svc)

// 		err := svc.SetSessionData(ctx, session.UUID, "", "value")
// 		require.Error(t, err)
// 		assert.Contains(t, err.Error(), "key cannot be empty")
// 	})

// 	t.Run("temporary data with zero TTL", func(t *testing.T) {
// 		err := svc.SetTemporaryData(ctx, "tempkey", "value", 0)
// 		require.Error(t, err)
// 		assert.Contains(t, err.Error(), "TTL must be positive")
// 	})
// }
// func TestSessionService_ConcurrencyEdgeCases(t *testing.T) {
// 	client := setupTestRedis()
// 	defer cleanupTestRedis(t, client)

// 	repo := NewGurdianRedisSessionRepository(client)
// 	svc := NewGourdianSessionService(repo, testConfig())
// 	ctx := context.Background()

// 	t.Run("concurrent session validation", func(t *testing.T) {
// 		session, _ := createTestSession(t, svc)
// 		var wg sync.WaitGroup
// 		errChan := make(chan error, 10)

// 		for i := 0; i < 10; i++ {
// 			wg.Add(1)
// 			go func() {
// 				defer wg.Done()
// 				_, err := svc.ValidateSession(ctx, session.UUID)
// 				errChan <- err
// 			}()
// 		}

// 		wg.Wait()
// 		close(errChan)

// 		for err := range errChan {
// 			require.NoError(t, err)
// 		}
// 	})

// 	t.Run("concurrent session revocation", func(t *testing.T) {
// 		session, _ := createTestSession(t, svc)
// 		var wg sync.WaitGroup
// 		errChan := make(chan error, 5)

// 		for i := 0; i < 5; i++ {
// 			wg.Add(1)
// 			go func() {
// 				defer wg.Done()
// 				err := svc.RevokeSession(ctx, session.UUID)
// 				errChan <- err
// 			}()
// 		}

// 		wg.Wait()
// 		close(errChan)

// 		// Only one revocation should succeed, others may fail
// 		var successCount int
// 		for err := range errChan {
// 			if err == nil {
// 				successCount++
// 			} else {
// 				assert.Contains(t, err.Error(), "session not found")
// 			}
// 		}
// 		assert.Equal(t, 1, successCount)
// 	})

// 	t.Run("concurrent session data operations", func(t *testing.T) {
// 		session, _ := createTestSession(t, svc)
// 		key := "concurrent_key"
// 		var wg sync.WaitGroup

// 		// Set initial value
// 		err := svc.SetSessionData(ctx, session.UUID, key, 0)
// 		require.NoError(t, err)

// 		// Run concurrent increments
// 		for i := 0; i < 10; i++ {
// 			wg.Add(1)
// 			go func() {
// 				defer wg.Done()
// 				// Get current value
// 				val, err := svc.GetSessionData(ctx, session.UUID, key)
// 				if err != nil {
// 					return
// 				}

// 				// Increment and set back
// 				num, ok := val.(float64)
// 				if !ok {
// 					return
// 				}
// 				_ = svc.SetSessionData(ctx, session.UUID, key, num+1)
// 			}()
// 		}

// 		wg.Wait()

// 		// Verify final value - may not be 10 due to race conditions
// 		finalVal, err := svc.GetSessionData(ctx, session.UUID, key)
// 		require.NoError(t, err)
// 		assert.Greater(t, finalVal.(float64), float64(0))
// 		assert.LessOrEqual(t, finalVal.(float64), float64(10))
// 	})
// }

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

	t.Run("concurrent session creation", func(t *testing.T) {
		userID := uuid.New()
		username := "testuser"
		ip := "192.168.1.1"
		ua := "test-agent"
		roles := []Role{}

		// Create multiple sessions in parallel
		var sessions []*GourdianSessionType
		errs := make(chan error, 5)
		results := make(chan *GourdianSessionType, 5)

		for i := 0; i < 5; i++ {
			go func() {
				session, err := svc.CreateSession(ctx, userID, username, &ip, &ua, roles)
				errs <- err
				results <- session
			}()
		}

		for i := 0; i < 5; i++ {
			err := <-errs
			require.NoError(t, err)
			session := <-results
			require.NotNil(t, session)
			sessions = append(sessions, session)
		}

		// Verify all sessions were created
		activeSessions, err := svc.GetActiveUserSessions(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, 5, len(activeSessions))
	})

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

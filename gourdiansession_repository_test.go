package gourdiansession

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiansession/errs"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type RedisRepositoryTestSuite struct {
	suite.Suite
	client     *redis.Client
	repository GurdianSessionRepositoryInt
	ctx        context.Context
}

func (suite *RedisRepositoryTestSuite) SetupSuite() {
	suite.client = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "GourdianRedisSecret",
		DB:       0,
	})
	suite.repository = NewGurdianRedisSessionRepository(suite.client)
	suite.ctx = context.Background()

	// Flush DB before tests
	err := suite.client.FlushDB(suite.ctx).Err()
	assert.NoError(suite.T(), err)
}

func (suite *RedisRepositoryTestSuite) TearDownTest() {
	// Flush DB after each test
	err := suite.client.FlushDB(suite.ctx).Err()
	assert.NoError(suite.T(), err)
}

func (suite *RedisRepositoryTestSuite) TestCreateAndGetSession() {
	userID := uuid.New()
	username := "testuser"
	ipAddress := "192.168.1.1"
	userAgent := "test-agent"
	roles := []Role{
		{
			Name: "admin",
			Permissions: []Permission{
				{
					Name:     "read",
					Resource: "users",
					Action:   "read",
				},
			},
		},
	}

	// Create a new session
	session := NewGurdianSessionObject(
		userID,
		username,
		&ipAddress,
		&userAgent,
		roles,
		1*time.Hour,
	)

	createdSession, err := suite.repository.CreateSession(suite.ctx, session)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), createdSession)
	assert.Equal(suite.T(), username, createdSession.Username)
	assert.Equal(suite.T(), userID, createdSession.UserID)
	assert.Equal(suite.T(), ipAddress, *createdSession.IPAddress)
	assert.Equal(suite.T(), userAgent, *createdSession.UserAgent)
	assert.Equal(suite.T(), SessionStatusActive, createdSession.Status)
	assert.True(suite.T(), createdSession.Authenticated)

	// Get the session
	retrievedSession, err := suite.repository.GetSessionByID(suite.ctx, createdSession.UUID)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), createdSession.UUID, retrievedSession.UUID)
	assert.Equal(suite.T(), createdSession.UserID, retrievedSession.UserID)
	assert.Equal(suite.T(), createdSession.Username, retrievedSession.Username)
	assert.Equal(suite.T(), *createdSession.IPAddress, *retrievedSession.IPAddress)
	assert.Equal(suite.T(), *createdSession.UserAgent, *retrievedSession.UserAgent)
	assert.Equal(suite.T(), createdSession.Status, retrievedSession.Status)
	assert.Equal(suite.T(), createdSession.Authenticated, retrievedSession.Authenticated)
}

func (suite *RedisRepositoryTestSuite) TestUpdateSession() {
	userID := uuid.New()
	session := NewGurdianSessionObject(
		userID,
		"testuser",
		nil,
		nil,
		nil,
		1*time.Hour,
	)

	createdSession, err := suite.repository.CreateSession(suite.ctx, session)
	assert.NoError(suite.T(), err)

	// Update the session
	createdSession.Username = "updateduser"
	createdSession.Status = SessionStatusRevoked
	updatedSession, err := suite.repository.UpdateSession(suite.ctx, createdSession)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "updateduser", updatedSession.Username)
	assert.Equal(suite.T(), SessionStatusRevoked, updatedSession.Status)

	// Verify update
	retrievedSession, err := suite.repository.GetSessionByID(suite.ctx, createdSession.UUID)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "updateduser", retrievedSession.Username)
	assert.Equal(suite.T(), SessionStatusRevoked, retrievedSession.Status)
}

func (suite *RedisRepositoryTestSuite) TestDeleteSession() {
	userID := uuid.New()
	session := NewGurdianSessionObject(
		userID,
		"testuser",
		nil,
		nil,
		nil,
		1*time.Hour,
	)

	createdSession, err := suite.repository.CreateSession(suite.ctx, session)
	assert.NoError(suite.T(), err)

	// Delete the session
	err = suite.repository.DeleteSession(suite.ctx, createdSession.UUID)
	assert.NoError(suite.T(), err)

	// Verify deletion
	_, err = suite.repository.GetSessionByID(suite.ctx, createdSession.UUID)
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), errs.ErrNotFound, err)
}

func (suite *RedisRepositoryTestSuite) TestRevokeSession() {
	userID := uuid.New()
	session := NewGurdianSessionObject(
		userID,
		"testuser",
		nil,
		nil,
		nil,
		1*time.Hour,
	)

	createdSession, err := suite.repository.CreateSession(suite.ctx, session)
	assert.NoError(suite.T(), err)

	// Revoke the session
	err = suite.repository.RevokeSessionByID(suite.ctx, createdSession.UUID)
	assert.NoError(suite.T(), err)

	// Verify revocation
	retrievedSession, err := suite.repository.GetSessionByID(suite.ctx, createdSession.UUID)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), SessionStatusRevoked, retrievedSession.Status)
	assert.True(suite.T(), time.Now().After(retrievedSession.ExpiresAt))
}

func (suite *RedisRepositoryTestSuite) TestGetSessionsByUserID() {
	userID := uuid.New()
	otherUserID := uuid.New()

	// Create 3 sessions for user
	for i := 0; i < 3; i++ {
		session := NewGurdianSessionObject(
			userID,
			"testuser",
			nil,
			nil,
			nil,
			1*time.Hour,
		)
		_, err := suite.repository.CreateSession(suite.ctx, session)
		assert.NoError(suite.T(), err)
	}

	// Create 2 sessions for other user
	for i := 0; i < 2; i++ {
		session := NewGurdianSessionObject(
			otherUserID,
			"otheruser",
			nil,
			nil,
			nil,
			1*time.Hour,
		)
		_, err := suite.repository.CreateSession(suite.ctx, session)
		assert.NoError(suite.T(), err)
	}

	// Get sessions for user
	sessions, err := suite.repository.GetSessionsByUserID(suite.ctx, userID)
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), sessions, 3)
	for _, session := range sessions {
		assert.Equal(suite.T(), userID, session.UserID)
	}

	// Get sessions for other user
	otherSessions, err := suite.repository.GetSessionsByUserID(suite.ctx, otherUserID)
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), otherSessions, 2)
	for _, session := range otherSessions {
		assert.Equal(suite.T(), otherUserID, session.UserID)
	}
}

func (suite *RedisRepositoryTestSuite) TestGetActiveSessionsByUserID() {
	userID := uuid.New()

	// Create active sessions
	for i := 0; i < 2; i++ {
		session := NewGurdianSessionObject(
			userID,
			"testuser",
			nil,
			nil,
			nil,
			1*time.Hour,
		)
		_, err := suite.repository.CreateSession(suite.ctx, session)
		assert.NoError(suite.T(), err)
	}

	// Create expired session
	expiredSession := NewGurdianSessionObject(
		userID,
		"testuser",
		nil,
		nil,
		nil,
		1*time.Hour,
	)
	expiredSession.Status = SessionStatusExpired
	expiredSession.ExpiresAt = time.Now().Add(-1 * time.Hour)
	_, err := suite.repository.CreateSession(suite.ctx, expiredSession)
	assert.NoError(suite.T(), err)

	// Create revoked session
	revokedSession := NewGurdianSessionObject(
		userID,
		"testuser",
		nil,
		nil,
		nil,
		1*time.Hour,
	)
	revokedSession.Status = SessionStatusRevoked
	_, err = suite.repository.CreateSession(suite.ctx, revokedSession)
	assert.NoError(suite.T(), err)

	// Get active sessions
	activeSessions, err := suite.repository.GetActiveSessionsByUserID(suite.ctx, userID)
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), activeSessions, 2)
	for _, session := range activeSessions {
		assert.Equal(suite.T(), SessionStatusActive, session.Status)
		assert.True(suite.T(), session.ExpiresAt.After(time.Now()))
	}
}

func (suite *RedisRepositoryTestSuite) TestRevokeUserSessions() {
	userID := uuid.New()

	// Create 3 active sessions for user
	for i := 0; i < 3; i++ {
		session := NewGurdianSessionObject(
			userID,
			"testuser",
			nil,
			nil,
			nil,
			1*time.Hour,
		)
		_, err := suite.repository.CreateSession(suite.ctx, session)
		assert.NoError(suite.T(), err)
	}

	// Revoke all sessions
	err := suite.repository.RevokeUserSessions(suite.ctx, userID)
	assert.NoError(suite.T(), err)

	// Verify all sessions are revoked
	sessions, err := suite.repository.GetSessionsByUserID(suite.ctx, userID)
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), sessions, 3)
	for _, session := range sessions {
		assert.Equal(suite.T(), SessionStatusRevoked, session.Status)
	}
}

func (suite *RedisRepositoryTestSuite) TestRevokeSessionsExcept() {
	userID := uuid.New()
	var keepSessionID uuid.UUID

	// Create 3 active sessions for user
	for i := 0; i < 3; i++ {
		session := NewGurdianSessionObject(
			userID,
			"testuser",
			nil,
			nil,
			nil,
			1*time.Hour,
		)
		createdSession, err := suite.repository.CreateSession(suite.ctx, session)
		assert.NoError(suite.T(), err)
		if i == 1 {
			keepSessionID = createdSession.UUID
		}
	}

	// Revoke all sessions except one
	err := suite.repository.RevokeSessionsExcept(suite.ctx, userID, keepSessionID)
	assert.NoError(suite.T(), err)

	// Verify sessions
	sessions, err := suite.repository.GetSessionsByUserID(suite.ctx, userID)
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), sessions, 3)

	var keptSession *GourdianSessionType
	for _, session := range sessions {
		if session.UUID == keepSessionID {
			keptSession = session
			assert.Equal(suite.T(), SessionStatusActive, session.Status)
		} else {
			assert.Equal(suite.T(), SessionStatusRevoked, session.Status)
		}
	}
	assert.NotNil(suite.T(), keptSession)
}

func (suite *RedisRepositoryTestSuite) TestExtendSession() {
	userID := uuid.New()
	session := NewGurdianSessionObject(
		userID,
		"testuser",
		nil,
		nil,
		nil,
		1*time.Hour,
	)

	createdSession, err := suite.repository.CreateSession(suite.ctx, session)
	assert.NoError(suite.T(), err)

	originalExpiry := createdSession.ExpiresAt

	// Extend session by 2 hours
	err = suite.repository.ExtendSession(suite.ctx, createdSession.UUID, 2*time.Hour)
	assert.NoError(suite.T(), err)

	// Verify extension
	updatedSession, err := suite.repository.GetSessionByID(suite.ctx, createdSession.UUID)
	assert.NoError(suite.T(), err)
	assert.True(suite.T(), updatedSession.ExpiresAt.After(originalExpiry))
	assert.WithinDuration(suite.T(), originalExpiry.Add(2*time.Hour), updatedSession.ExpiresAt, time.Second)
}

func (suite *RedisRepositoryTestSuite) TestUpdateSessionActivity() {
	userID := uuid.New()
	session := NewGurdianSessionObject(
		userID,
		"testuser",
		nil,
		nil,
		nil,
		1*time.Hour,
	)

	createdSession, err := suite.repository.CreateSession(suite.ctx, session)
	assert.NoError(suite.T(), err)

	originalActivity := createdSession.LastActivity

	// Wait a bit to ensure time changes
	time.Sleep(10 * time.Millisecond)

	// Update activity
	err = suite.repository.UpdateSessionActivity(suite.ctx, createdSession.UUID)
	assert.NoError(suite.T(), err)

	// Verify update
	updatedSession, err := suite.repository.GetSessionByID(suite.ctx, createdSession.UUID)
	assert.NoError(suite.T(), err)
	assert.True(suite.T(), updatedSession.LastActivity.After(originalActivity))
}

func (suite *RedisRepositoryTestSuite) TestValidateSessionByID() {
	userID := uuid.New()

	// Create active session
	activeSession := NewGurdianSessionObject(
		userID,
		"testuser",
		nil,
		nil,
		nil,
		1*time.Hour,
	)
	createdActiveSession, err := suite.repository.CreateSession(suite.ctx, activeSession)
	assert.NoError(suite.T(), err)

	// Create expired session
	expiredSession := NewGurdianSessionObject(
		userID,
		"testuser",
		nil,
		nil,
		nil,
		-1*time.Hour, // already expired
	)
	createdExpiredSession, err := suite.repository.CreateSession(suite.ctx, expiredSession)
	assert.NoError(suite.T(), err)

	// Create revoked session
	revokedSession := NewGurdianSessionObject(
		userID,
		"testuser",
		nil,
		nil,
		nil,
		1*time.Hour,
	)
	revokedSession.Status = SessionStatusRevoked
	createdRevokedSession, err := suite.repository.CreateSession(suite.ctx, revokedSession)
	assert.NoError(suite.T(), err)

	// Test active session
	validSession, err := suite.repository.ValidateSessionByID(suite.ctx, createdActiveSession.UUID)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), createdActiveSession.UUID, validSession.UUID)
	assert.Equal(suite.T(), SessionStatusActive, validSession.Status)

	// Test expired session
	_, err = suite.repository.ValidateSessionByID(suite.ctx, createdExpiredSession.UUID)
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), errs.ErrInvalidSession, err)

	// Test revoked session
	_, err = suite.repository.ValidateSessionByID(suite.ctx, createdRevokedSession.UUID)
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), errs.ErrInvalidSession, err)
}

func (suite *RedisRepositoryTestSuite) TestValidateSessionByIDIPUA() {
	userID := uuid.New()
	ipAddress := "192.168.1.1"
	userAgent := "test-agent"

	// Create session with IP and UA
	session := NewGurdianSessionObject(
		userID,
		"testuser",
		&ipAddress,
		&userAgent,
		nil,
		1*time.Hour,
	)
	createdSession, err := suite.repository.CreateSession(suite.ctx, session)
	assert.NoError(suite.T(), err)

	// Test with correct IP and UA
	validSession, err := suite.repository.ValidateSessionByIDIPUA(suite.ctx, createdSession.UUID, ipAddress, userAgent)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), createdSession.UUID, validSession.UUID)

	// Test with wrong IP
	_, err = suite.repository.ValidateSessionByIDIPUA(suite.ctx, createdSession.UUID, "10.0.0.1", userAgent)
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), errs.ErrInvalidSession, err)

	// Test with wrong UA
	_, err = suite.repository.ValidateSessionByIDIPUA(suite.ctx, createdSession.UUID, ipAddress, "wrong-agent")
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), errs.ErrInvalidSession, err)
}

func (suite *RedisRepositoryTestSuite) TestSessionDataOperations() {
	userID := uuid.New()
	session := NewGurdianSessionObject(
		userID,
		"testuser",
		nil,
		nil,
		nil,
		1*time.Hour,
	)

	createdSession, err := suite.repository.CreateSession(suite.ctx, session)
	assert.NoError(suite.T(), err)

	// Set data
	testData := map[string]interface{}{
		"string": "value",
		"number": 42,
		"bool":   true,
		"object": map[string]interface{}{"key": "value"},
	}

	for key, value := range testData {
		err = suite.repository.SetSessionData(suite.ctx, createdSession.UUID, key, value)
		assert.NoError(suite.T(), err)
	}

	// Get data
	for key, expectedValue := range testData {
		value, err := suite.repository.GetSessionData(suite.ctx, createdSession.UUID, key)
		assert.NoError(suite.T(), err)
		assert.Equal(suite.T(), expectedValue, value)
	}

	// Get non-existent data
	_, err = suite.repository.GetSessionData(suite.ctx, createdSession.UUID, "nonexistent")
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), errs.ErrNotFound, err)

	// Delete data
	for key := range testData {
		err = suite.repository.DeleteSessionData(suite.ctx, createdSession.UUID, key)
		assert.NoError(suite.T(), err)

		_, err = suite.repository.GetSessionData(suite.ctx, createdSession.UUID, key)
		assert.Error(suite.T(), err)
		assert.Equal(suite.T(), errs.ErrNotFound, err)
	}
}

func (suite *RedisRepositoryTestSuite) TestTemporaryDataOperations() {
	// Set temporary data
	testData := map[string]interface{}{
		"temp1": "value1",
		"temp2": 123,
		"temp3": false,
	}

	for key, value := range testData {
		err := suite.repository.SetTemporaryData(suite.ctx, key, value, 1*time.Hour)
		assert.NoError(suite.T(), err)
	}

	// Get temporary data
	for key, expectedValue := range testData {
		value, err := suite.repository.GetTemporaryData(suite.ctx, key)
		assert.NoError(suite.T(), err)
		assert.Equal(suite.T(), expectedValue, value)
	}

	// Get non-existent data
	_, err := suite.repository.GetTemporaryData(suite.ctx, "nonexistent")
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), errs.ErrNotFound, err)

	// Delete temporary data
	for key := range testData {
		err = suite.repository.DeleteTemporaryData(suite.ctx, key)
		assert.NoError(suite.T(), err)

		_, err = suite.repository.GetTemporaryData(suite.ctx, key)
		assert.Error(suite.T(), err)
		assert.Equal(suite.T(), errs.ErrNotFound, err)
	}
}

func TestRedisRepositoryTestSuite(t *testing.T) {
	suite.Run(t, new(RedisRepositoryTestSuite))
}

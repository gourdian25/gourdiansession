package gourdiansession

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gourdian25/gourdiansession/errs"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type SessionServiceTestSuite struct {
	suite.Suite
	client     *redis.Client
	repository GurdianSessionRepositoryInt
	service    GourdianSessionServiceInt
	ctx        context.Context
}

func (suite *SessionServiceTestSuite) SetupSuite() {
	suite.client = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "GourdianRedisSecret",
		DB:       0,
	})
	suite.repository = NewGurdianRedisSessionRepository(suite.client)

	config := &GourdianSessionConfig{
		MaxUserSessions:            5,
		MaxSessionsPerDevice:       3,
		MaxIPConnections:           2,
		AllowConcurrentSessions:    false,
		TrackIPAddresses:           true,
		TrackClientDevices:         true,
		DefaultSessionDuration:     1 * time.Hour,
		IdleTimeoutDuration:        30 * time.Minute,
		SessionRenewalWindow:       15 * time.Minute,
		SessionCleanupInterval:     1 * time.Hour,
		AutoRevokeOnPasswordChange: true,
		BlockedUserAgents:          []string{"bad-bot", "scraper"},
	}

	suite.service = NewGourdianSessionService(suite.repository, config)
	suite.ctx = context.Background()

	// Flush DB before tests
	err := suite.client.FlushDB(suite.ctx).Err()
	assert.NoError(suite.T(), err)
}

func (suite *SessionServiceTestSuite) TearDownTest() {
	// Flush DB after each test
	err := suite.client.FlushDB(suite.ctx).Err()
	assert.NoError(suite.T(), err)
}

func (suite *SessionServiceTestSuite) TestCreateSession() {
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
	session, err := suite.service.CreateSession(suite.ctx, userID, username, &ipAddress, &userAgent, roles)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), session)
	assert.Equal(suite.T(), username, session.Username)
	assert.Equal(suite.T(), userID, session.UserID)
	assert.Equal(suite.T(), ipAddress, *session.IPAddress)
	assert.Equal(suite.T(), userAgent, *session.UserAgent)
	assert.Equal(suite.T(), SessionStatusActive, session.Status)
	assert.True(suite.T(), session.Authenticated)

	// Verify concurrent sessions are not allowed (based on config)
	otherSessions, err := suite.service.GetActiveUserSessions(suite.ctx, userID)
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), otherSessions, 1) // Only the current session should exist
}

func (suite *SessionServiceTestSuite) TestCreateSessionWithBlockedUserAgent() {
	userID := uuid.New()
	username := "testuser"
	ipAddress := "192.168.1.1"
	blockedUserAgent := "bad-bot/1.0"
	roles := []Role{}

	// Try to create session with blocked user agent
	_, err := suite.service.CreateSession(suite.ctx, userID, username, &ipAddress, &blockedUserAgent, roles)
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), errs.ErrForbidden, err)
}

func (suite *SessionServiceTestSuite) TestRevokeSession() {
	userID := uuid.New()
	session, err := suite.service.CreateSession(suite.ctx, userID, "testuser", nil, nil, nil)
	assert.NoError(suite.T(), err)

	// Revoke the session
	err = suite.service.RevokeSession(suite.ctx, session.UUID)
	assert.NoError(suite.T(), err)

	// Verify session is revoked
	revokedSession, err := suite.service.GetSession(suite.ctx, session.UUID)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), SessionStatusRevoked, revokedSession.Status)
}

func (suite *SessionServiceTestSuite) TestGetSession() {
	userID := uuid.New()
	createdSession, err := suite.service.CreateSession(suite.ctx, userID, "testuser", nil, nil, nil)
	assert.NoError(suite.T(), err)

	// Get the session
	retrievedSession, err := suite.service.GetSession(suite.ctx, createdSession.UUID)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), createdSession.UUID, retrievedSession.UUID)
	assert.Equal(suite.T(), createdSession.UserID, retrievedSession.UserID)
	assert.Equal(suite.T(), createdSession.Username, retrievedSession.Username)
}

func (suite *SessionServiceTestSuite) TestRefreshSession() {
	userID := uuid.New()
	createdSession, err := suite.service.CreateSession(suite.ctx, userID, "testuser", nil, nil, nil)
	assert.NoError(suite.T(), err)

	// Manually set expiry to be within renewal window
	createdSession.ExpiresAt = time.Now().Add(10 * time.Minute) // Within 15min renewal window
	_, err = suite.repository.UpdateSession(suite.ctx, createdSession)
	assert.NoError(suite.T(), err)

	// Refresh session
	refreshedSession, err := suite.service.RefreshSession(suite.ctx, createdSession.UUID)
	assert.NoError(suite.T(), err)
	assert.True(suite.T(), refreshedSession.ExpiresAt.After(createdSession.ExpiresAt))
	assert.WithinDuration(suite.T(), time.Now().Add(suite.service.(*GourdianSessionService).config.DefaultSessionDuration),
		refreshedSession.ExpiresAt, time.Second)
}

func (suite *SessionServiceTestSuite) TestExtendSession() {
	userID := uuid.New()
	createdSession, err := suite.service.CreateSession(suite.ctx, userID, "testuser", nil, nil, nil)
	assert.NoError(suite.T(), err)

	originalExpiry := createdSession.ExpiresAt

	// Extend session by 2 hours
	extendedSession, err := suite.service.ExtendSession(suite.ctx, createdSession.UUID, 2*time.Hour)
	assert.NoError(suite.T(), err)
	assert.True(suite.T(), extendedSession.ExpiresAt.After(originalExpiry))
	assert.WithinDuration(suite.T(), originalExpiry.Add(2*time.Hour), extendedSession.ExpiresAt, time.Second)
}

func (suite *SessionServiceTestSuite) TestUpdateSessionActivity() {
	userID := uuid.New()
	createdSession, err := suite.service.CreateSession(suite.ctx, userID, "testuser", nil, nil, nil)
	assert.NoError(suite.T(), err)

	originalActivity := createdSession.LastActivity

	// Wait a bit to ensure time changes
	time.Sleep(10 * time.Millisecond)

	// Update activity
	err = suite.service.UpdateSessionActivity(suite.ctx, createdSession.UUID)
	assert.NoError(suite.T(), err)

	// Verify update
	updatedSession, err := suite.service.GetSession(suite.ctx, createdSession.UUID)
	assert.NoError(suite.T(), err)
	assert.True(suite.T(), updatedSession.LastActivity.After(originalActivity))
}

func (suite *SessionServiceTestSuite) TestGetUserSessions() {
	userID := uuid.New()
	otherUserID := uuid.New()

	// Create 3 sessions for user
	for i := 0; i < 3; i++ {
		_, err := suite.service.CreateSession(suite.ctx, userID, "testuser", nil, nil, nil)
		assert.NoError(suite.T(), err)
	}

	// Create 2 sessions for other user
	for i := 0; i < 2; i++ {
		_, err := suite.service.CreateSession(suite.ctx, otherUserID, "otheruser", nil, nil, nil)
		assert.NoError(suite.T(), err)
	}

	// Get sessions for user
	sessions, err := suite.service.GetUserSessions(suite.ctx, userID)
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), sessions, 3)
	for _, session := range sessions {
		assert.Equal(suite.T(), userID, session.UserID)
	}

	// Get sessions for other user
	otherSessions, err := suite.service.GetUserSessions(suite.ctx, otherUserID)
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), otherSessions, 2)
	for _, session := range otherSessions {
		assert.Equal(suite.T(), otherUserID, session.UserID)
	}
}

func (suite *SessionServiceTestSuite) TestGetActiveUserSessions() {
	userID := uuid.New()

	// Create 2 active sessions
	for i := 0; i < 2; i++ {
		_, err := suite.service.CreateSession(suite.ctx, userID, "testuser", nil, nil, nil)
		assert.NoError(suite.T(), err)
	}

	// Create an expired session (by creating with negative duration)
	expiredSession := NewGurdianSessionObject(
		userID,
		"testuser",
		nil,
		nil,
		nil,
		-1*time.Hour,
	)
	_, err := suite.repository.CreateSession(suite.ctx, expiredSession)
	assert.NoError(suite.T(), err)

	// Get active sessions
	activeSessions, err := suite.service.GetActiveUserSessions(suite.ctx, userID)
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), activeSessions, 2)
	for _, session := range activeSessions {
		assert.Equal(suite.T(), SessionStatusActive, session.Status)
		assert.True(suite.T(), session.ExpiresAt.After(time.Now()))
	}
}

func (suite *SessionServiceTestSuite) TestRevokeAllUserSessions() {
	userID := uuid.New()

	// Create 3 active sessions
	for i := 0; i < 3; i++ {
		_, err := suite.service.CreateSession(suite.ctx, userID, "testuser", nil, nil, nil)
		assert.NoError(suite.T(), err)
	}

	// Revoke all sessions
	err := suite.service.RevokeAllUserSessions(suite.ctx, userID)
	assert.NoError(suite.T(), err)

	// Verify all sessions are revoked
	sessions, err := suite.service.GetUserSessions(suite.ctx, userID)
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), sessions, 3)
	for _, session := range sessions {
		assert.Equal(suite.T(), SessionStatusRevoked, session.Status)
	}
}

func (suite *SessionServiceTestSuite) TestRevokeOtherUserSessions() {
	userID := uuid.New()
	var keepSessionID uuid.UUID

	// Create 3 active sessions
	for i := 0; i < 3; i++ {
		session, err := suite.service.CreateSession(suite.ctx, userID, "testuser", nil, nil, nil)
		assert.NoError(suite.T(), err)
		if i == 1 {
			keepSessionID = session.UUID
		}
	}

	// Revoke other sessions
	err := suite.service.RevokeOtherUserSessions(suite.ctx, userID, keepSessionID)
	assert.NoError(suite.T(), err)

	// Verify sessions
	sessions, err := suite.service.GetUserSessions(suite.ctx, userID)
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

func (suite *SessionServiceTestSuite) TestValidateSession() {
	userID := uuid.New()
	createdSession, err := suite.service.CreateSession(suite.ctx, userID, "testuser", nil, nil, nil)
	assert.NoError(suite.T(), err)

	// Validate active session
	validSession, err := suite.service.ValidateSession(suite.ctx, createdSession.UUID)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), createdSession.UUID, validSession.UUID)
	assert.Equal(suite.T(), SessionStatusActive, validSession.Status)

	// Create an expired session
	expiredSession := NewGurdianSessionObject(
		userID,
		"testuser",
		nil,
		nil,
		nil,
		-1*time.Hour,
	)
	createdExpiredSession, err := suite.repository.CreateSession(suite.ctx, expiredSession)
	assert.NoError(suite.T(), err)

	// Validate expired session
	_, err = suite.service.ValidateSession(suite.ctx, createdExpiredSession.UUID)
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), errs.ErrInvalidSession, err)

	// Create a revoked session
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

	// Validate revoked session
	_, err = suite.service.ValidateSession(suite.ctx, createdRevokedSession.UUID)
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), errs.ErrInvalidSession, err)
}

func (suite *SessionServiceTestSuite) TestValidateSessionWithContext() {
	userID := uuid.New()
	ipAddress := "192.168.1.1"
	userAgent := "test-agent"

	// Create session with IP and UA
	createdSession, err := suite.service.CreateSession(suite.ctx, userID, "testuser", &ipAddress, &userAgent, nil)
	assert.NoError(suite.T(), err)

	// Validate with correct context
	validSession, err := suite.service.ValidateSessionWithContext(suite.ctx, createdSession.UUID, ipAddress, userAgent)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), createdSession.UUID, validSession.UUID)

	// Validate with wrong IP
	_, err = suite.service.ValidateSessionWithContext(suite.ctx, createdSession.UUID, "10.0.0.1", userAgent)
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), errs.ErrInvalidSession, err)

	// Validate with wrong UA
	_, err = suite.service.ValidateSessionWithContext(suite.ctx, createdSession.UUID, ipAddress, "wrong-agent")
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), errs.ErrInvalidSession, err)
}

func (suite *SessionServiceTestSuite) TestSessionDataOperations() {
	userID := uuid.New()
	createdSession, err := suite.service.CreateSession(suite.ctx, userID, "testuser", nil, nil, nil)
	assert.NoError(suite.T(), err)

	// Set data
	testData := map[string]interface{}{
		"string": "value",
		"number": 42,
		"bool":   true,
		"object": map[string]interface{}{"key": "value"},
	}

	for key, value := range testData {
		err = suite.service.SetSessionData(suite.ctx, createdSession.UUID, key, value)
		assert.NoError(suite.T(), err)
	}

	// Get data
	for key, expectedValue := range testData {
		value, err := suite.service.GetSessionData(suite.ctx, createdSession.UUID, key)
		assert.NoError(suite.T(), err)
		assert.Equal(suite.T(), expectedValue, value)
	}

	// Get non-existent data
	_, err = suite.service.GetSessionData(suite.ctx, createdSession.UUID, "nonexistent")
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), errs.ErrNotFound, err)

	// Delete data
	for key := range testData {
		err = suite.service.DeleteSessionData(suite.ctx, createdSession.UUID, key)
		assert.NoError(suite.T(), err)

		_, err = suite.service.GetSessionData(suite.ctx, createdSession.UUID, key)
		assert.Error(suite.T(), err)
		assert.Equal(suite.T(), errs.ErrNotFound, err)
	}
}

func (suite *SessionServiceTestSuite) TestTemporaryDataOperations() {
	// Set temporary data
	testData := map[string]interface{}{
		"temp1": "value1",
		"temp2": 123,
		"temp3": false,
	}

	for key, value := range testData {
		err := suite.service.SetTemporaryData(suite.ctx, key, value, 1*time.Hour)
		assert.NoError(suite.T(), err)
	}

	// Get temporary data
	for key, expectedValue := range testData {
		value, err := suite.service.GetTemporaryData(suite.ctx, key)
		assert.NoError(suite.T(), err)
		assert.Equal(suite.T(), expectedValue, value)
	}

	// Get non-existent data
	_, err := suite.service.GetTemporaryData(suite.ctx, "nonexistent")
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), errs.ErrNotFound, err)

	// Delete temporary data
	for key := range testData {
		err = suite.service.DeleteTemporaryData(suite.ctx, key)
		assert.NoError(suite.T(), err)

		_, err = suite.service.GetTemporaryData(suite.ctx, key)
		assert.Error(suite.T(), err)
		assert.Equal(suite.T(), errs.ErrNotFound, err)
	}
}

func (suite *SessionServiceTestSuite) TestCheckSessionQuota() {
	userID := uuid.New()
	ipAddress := "192.168.1.1"
	userAgent := "test-agent"

	// Test max user sessions (config is set to 5 in SetupSuite)
	for i := 0; i < 5; i++ {
		err := suite.service.CheckSessionQuota(suite.ctx, userID, &ipAddress, &userAgent)
		assert.NoError(suite.T(), err)

		_, err = suite.service.CreateSession(suite.ctx, userID, "testuser", &ipAddress, &userAgent, nil)
		assert.NoError(suite.T(), err)
	}

	// Should hit max user sessions limit
	err := suite.service.CheckSessionQuota(suite.ctx, userID, &ipAddress, &userAgent)
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), errs.ErrForbidden, err)

	// Test max sessions per device (config is set to 3)
	// Create sessions with same user agent but different IP
	for i := 0; i < 3; i++ {
		newIP := fmt.Sprintf("192.168.1.%d", i+2)
		_, err := suite.service.CreateSession(suite.ctx, userID, "testuser", &newIP, &userAgent, nil)
		assert.NoError(suite.T(), err)
	}

	// Should hit max sessions per device limit
	newIP := "192.168.1.100"
	err = suite.service.CheckSessionQuota(suite.ctx, userID, &newIP, &userAgent)
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), errs.ErrForbidden, err)

	// Test max IP connections (config is set to 2)
	// Create sessions with same IP but different user agents
	newUserAgent := "other-agent"
	for i := 0; i < 2; i++ {
		ua := fmt.Sprintf("%s-%d", newUserAgent, i)
		_, err := suite.service.CreateSession(suite.ctx, userID, "testuser", &ipAddress, &ua, nil)
		assert.NoError(suite.T(), err)
	}

	// Should hit max IP connections limit
	ua := "another-agent"
	err = suite.service.CheckSessionQuota(suite.ctx, userID, &ipAddress, &ua)
	assert.Error(suite.T(), err)
	assert.Equal(suite.T(), errs.ErrForbidden, err)
}

func (suite *SessionServiceTestSuite) TestEnforceSessionLimits() {
	userID := uuid.New()
	ipAddress := "192.168.1.1"
	userAgent := "test-agent"

	// With AllowConcurrentSessions=false (set in config), should only allow one session
	firstSession, err := suite.service.CreateSession(suite.ctx, userID, "testuser", &ipAddress, &userAgent, nil)
	assert.NoError(suite.T(), err)

	// Second session should revoke the first one
	secondSession, err := suite.service.CreateSession(suite.ctx, userID, "testuser", &ipAddress, &userAgent, nil)
	assert.NoError(suite.T(), err)

	// Verify first session is revoked
	firstSession, err = suite.service.GetSession(suite.ctx, firstSession.UUID)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), SessionStatusRevoked, firstSession.Status)

	// Verify second session is active
	secondSession, err = suite.service.GetSession(suite.ctx, secondSession.UUID)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), SessionStatusActive, secondSession.Status)

	// Verify only one active session exists
	activeSessions, err := suite.service.GetActiveUserSessions(suite.ctx, userID)
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), activeSessions, 1)
	assert.Equal(suite.T(), secondSession.UUID, activeSessions[0].UUID)
}

func TestSessionServiceTestSuite(t *testing.T) {
	suite.Run(t, new(SessionServiceTestSuite))
}

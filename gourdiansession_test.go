// File: gourdiansession_test.go

// gourdiansession_test.go
package gourdiansession

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func setupTestRedis() *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "GourdianRedisSecret",
		DB:       15,
	})
}

func cleanupTestRedis(t *testing.T, client *redis.Client) {
	err := client.FlushDB(context.Background()).Err()
	require.NoError(t, err)
}

func setupTestMongoDB(t *testing.T) *mongo.Database {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://root:GourdianMongoSecret@localhost:27017/GourdianMongoDB?authSource=admin"))
	require.NoError(t, err)

	db := client.Database("test_gourdian_sessions")
	return db
}

func cleanupTestMongoDB(t *testing.T, db *mongo.Database) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := db.Drop(ctx)
	require.NoError(t, err)
}

func strPtr(s string) *string {
	return &s
}

func testConfig() *GourdianSessionConfig {
	return &GourdianSessionConfig{
		MaxUserSessions:            5,
		MaxSessionsPerDevice:       2,
		MaxIPConnections:           3,
		AllowConcurrentSessions:    true,
		TrackIPAddresses:           true,
		TrackClientDevices:         true,
		DefaultSessionDuration:     30 * time.Minute,
		IdleTimeoutDuration:        15 * time.Minute,
		SessionRenewalWindow:       5 * time.Minute,
		SessionCleanupInterval:     1 * time.Hour,
		AutoRevokeOnPasswordChange: true,
		BlockedUserAgents:          []string{"badbot", "scraper"},
	}
}

func createTestSession(t *testing.T, svc GourdianSessionServiceInt) (*GourdianSessionType, uuid.UUID) {
	userID := uuid.New()
	username := "testuser"
	ip := "192.168.1.1"
	ua := "test-agent"
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

	session, err := svc.CreateSession(context.Background(), userID, username, &ip, &ua, roles)
	require.NoError(t, err)
	require.NotNil(t, session)

	return session, userID
}

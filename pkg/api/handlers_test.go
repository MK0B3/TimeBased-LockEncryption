package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"timelock-capsule/pkg/storage"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Note: These tests focus on API logic and HTTP handling.
// Full integration tests with real drand and crypto are in pkg/crypto/ibe_test.go

// TestHealthCheck tests the health check endpoint
func TestHealthCheck(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create simple handler with nil dependencies (health check doesn't use them)
	handler := &Handler{}

	router := gin.New()
	router.GET("/api/health", handler.HealthCheck)

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "healthy", response["status"])
	assert.NotNil(t, response["time"])
}

// TestGetCapsuleNotFound tests retrieving a non-existent capsule
func TestGetCapsuleNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create temporary storage
	store, err := storage.NewStore(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer store.Close()

	handler := &Handler{
		store: store,
	}

	router := gin.New()
	router.GET("/api/capsules/:id", handler.GetCapsule)

	req := httptest.NewRequest(http.MethodGet, "/api/capsules/nonexistent", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Contains(t, response["error"], "not found")
}

// TestGetCapsule tests retrieving an existing capsule
func TestGetCapsule(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store, err := storage.NewStore(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer store.Close()

	handler := &Handler{
		store: store,
	}

	// Create a test capsule
	capsule := &storage.Capsule{
		ID:         "test-capsule-id",
		UnlockTime: time.Now().Add(1 * time.Hour),
		Round:      12345,
		Status:     storage.StatusLocked,
		CreatedAt:  time.Now(),
		Metadata: map[string]string{
			"test": "data",
		},
	}
	err = store.SaveCapsule(capsule)
	require.NoError(t, err)

	router := gin.New()
	router.GET("/api/capsules/:id", handler.GetCapsule)

	req := httptest.NewRequest(http.MethodGet, "/api/capsules/test-capsule-id", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response GetCapsuleResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "test-capsule-id", response.CapsuleID)
	assert.Equal(t, "locked", response.Status)
	assert.Equal(t, "data", response.Metadata["test"])
	assert.Empty(t, response.Message) // Locked capsules don't return the message
}

// TestGetCapsuleUnlocked tests retrieving an unlocked capsule with message
func TestGetCapsuleUnlocked(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store, err := storage.NewStore(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer store.Close()

	handler := &Handler{
		store: store,
	}

	// Create an unlocked capsule with decrypted message
	now := time.Now()
	capsule := &storage.Capsule{
		ID:           "unlocked-capsule",
		UnlockTime:   now.Add(-1 * time.Hour),
		Round:        100,
		Status:       storage.StatusUnlocked,
		CreatedAt:    now.Add(-2 * time.Hour),
		DecryptedAt:  &now,
		DecryptedMsg: []byte("Secret message revealed!"),
	}
	err = store.SaveCapsule(capsule)
	require.NoError(t, err)

	router := gin.New()
	router.GET("/api/capsules/:id", handler.GetCapsule)

	req := httptest.NewRequest(http.MethodGet, "/api/capsules/unlocked-capsule", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response GetCapsuleResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "unlocked-capsule", response.CapsuleID)
	assert.Equal(t, "unlocked", response.Status)
	assert.Equal(t, "Secret message revealed!", response.Message)
	assert.NotNil(t, response.DecryptedAt)
}

// TestListCapsules tests listing all capsules
func TestListCapsules(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store, err := storage.NewStore(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer store.Close()

	handler := &Handler{
		store: store,
	}

	// Create test capsules with different statuses
	capsules := []*storage.Capsule{
		{
			ID:         "locked-1",
			UnlockTime: time.Now().Add(1 * time.Hour),
			Round:      100,
			Status:     storage.StatusLocked,
			CreatedAt:  time.Now(),
		},
		{
			ID:         "locked-2",
			UnlockTime: time.Now().Add(2 * time.Hour),
			Round:      200,
			Status:     storage.StatusLocked,
			CreatedAt:  time.Now(),
		},
		{
			ID:         "unlocked-1",
			UnlockTime: time.Now().Add(-1 * time.Hour),
			Round:      50,
			Status:     storage.StatusUnlocked,
			CreatedAt:  time.Now(),
		},
	}

	for _, c := range capsules {
		err := store.SaveCapsule(c)
		require.NoError(t, err)
	}

	router := gin.New()
	router.GET("/api/capsules", handler.ListCapsules)

	req := httptest.NewRequest(http.MethodGet, "/api/capsules", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string][]GetCapsuleResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Len(t, response["capsules"], 3)
}

// TestListCapsulesByStatus tests filtering capsules by status
func TestListCapsulesByStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store, err := storage.NewStore(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer store.Close()

	handler := &Handler{
		store: store,
	}

	// Create capsules with different statuses
	locked := &storage.Capsule{
		ID:         "locked-capsule",
		UnlockTime: time.Now().Add(1 * time.Hour),
		Round:      100,
		Status:     storage.StatusLocked,
		CreatedAt:  time.Now(),
	}
	unlocked := &storage.Capsule{
		ID:         "unlocked-capsule",
		UnlockTime: time.Now().Add(-1 * time.Hour),
		Round:      50,
		Status:     storage.StatusUnlocked,
		CreatedAt:  time.Now(),
	}
	failed := &storage.Capsule{
		ID:         "failed-capsule",
		UnlockTime: time.Now().Add(-2 * time.Hour),
		Round:      25,
		Status:     storage.StatusFailed,
		CreatedAt:  time.Now(),
	}

	err = store.SaveCapsule(locked)
	require.NoError(t, err)
	err = store.SaveCapsule(unlocked)
	require.NoError(t, err)
	err = store.SaveCapsule(failed)
	require.NoError(t, err)

	router := gin.New()
	router.GET("/api/capsules", handler.ListCapsules)

	// Test filtering by locked status
	req := httptest.NewRequest(http.MethodGet, "/api/capsules?status=locked", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string][]GetCapsuleResponse
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Len(t, response["capsules"], 1)
	assert.Equal(t, "locked", response["capsules"][0].Status)
	assert.Equal(t, "locked-capsule", response["capsules"][0].CapsuleID)
}

// TestDeleteCapsule tests deleting a capsule
func TestDeleteCapsule(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store, err := storage.NewStore(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer store.Close()

	handler := &Handler{
		store: store,
	}

	// Create a test capsule
	capsule := &storage.Capsule{
		ID:         "delete-test",
		UnlockTime: time.Now().Add(1 * time.Hour),
		Round:      100,
		Status:     storage.StatusLocked,
		CreatedAt:  time.Now(),
	}
	err = store.SaveCapsule(capsule)
	require.NoError(t, err)

	router := gin.New()
	router.DELETE("/api/capsules/:id", handler.DeleteCapsule)

	// Delete the capsule
	req := httptest.NewRequest(http.MethodDelete, "/api/capsules/delete-test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Contains(t, response["message"], "deleted")

	// Verify capsule is deleted
	_, err = store.GetCapsule("delete-test")
	assert.Error(t, err)
}

// TestGetStats tests the stats endpoint
func TestGetStats(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store, err := storage.NewStore(t.TempDir() + "/test.db")
	require.NoError(t, err)
	defer store.Close()

	handler := &Handler{
		store: store,
	}

	// Create test capsules
	for i := 0; i < 5; i++ {
		status := storage.StatusLocked
		if i%2 == 0 {
			status = storage.StatusUnlocked
		}
		capsule := &storage.Capsule{
			ID:         string(rune('a' + i)),
			UnlockTime: time.Now().Add(time.Duration(i) * time.Hour),
			Round:      uint64(100 + i),
			Status:     status,
			CreatedAt:  time.Now(),
		}
		err := store.SaveCapsule(capsule)
		require.NoError(t, err)
	}

	router := gin.New()
	router.GET("/api/stats", handler.GetStats)

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	// Verify we got stats data back
	assert.NotNil(t, response)
}

// TestDecryptRequestValidation tests the decrypt endpoint input validation
func TestDecryptRequestValidation(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := &Handler{}

	router := gin.New()
	router.POST("/api/decrypt", handler.DecryptCapsule)

	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing ciphertext",
			body: `{"round": 12345}`,
		},
		{
			name: "missing round",
			body: `{"ciphertext": {"u": "test"}}`,
		},
		{
			name: "invalid json",
			body: `{invalid}`,
		},
		{
			name: "empty body",
			body: `{}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/decrypt", bytes.NewReader([]byte(tt.body)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)
			assert.Contains(t, response["error"], "Invalid request")
		})
	}
}

// TestGetBeaconSignatureInvalidRound tests the beacon signature endpoint with invalid round
func TestGetBeaconSignatureInvalidRound(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := &Handler{}

	router := gin.New()
	router.GET("/api/beacon/signature/:round", handler.GetBeaconSignature)

	req := httptest.NewRequest(http.MethodGet, "/api/beacon/signature/invalid", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Contains(t, response["error"], "Invalid round")
}

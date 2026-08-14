package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"timelock-capsule/pkg/beacon"
	"timelock-capsule/pkg/crypto"
	"timelock-capsule/pkg/storage"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// MaxMessageBytes bounds the plaintext a capsule will accept. tlock's hybrid
// encryption imposes no small limit of its own, so this is a sanity bound to keep
// a single capsule from filling the database, not a cryptographic constraint.
const MaxMessageBytes = 64 * 1024

type Handler struct {
	store  *storage.Store
	beacon *beacon.Client
}

func NewHandler(store *storage.Store, beaconClient *beacon.Client) *Handler {
	return &Handler{
		store:  store,
		beacon: beaconClient,
	}
}

type CreateCapsuleRequest struct {
	Message    string            `json:"message" binding:"required"`
	UnlockTime time.Time         `json:"unlock_time" binding:"required"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type CreateCapsuleResponse struct {
	CapsuleID   string      `json:"capsule_id"`
	UnlockTime  time.Time   `json:"unlock_time"`
	RoundNumber uint64      `json:"round_number"`
	Status      string      `json:"status"`
	Ciphertext  interface{} `json:"ciphertext"` //  actual encrypted data
}

type GetCapsuleResponse struct {
	CapsuleID   string            `json:"capsule_id"`
	Status      string            `json:"status"`
	UnlockTime  time.Time         `json:"unlock_time"`
	CreatedAt   time.Time         `json:"created_at"`
	DecryptedAt *time.Time        `json:"decrypted_at,omitempty"`
	Message     string            `json:"message,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

func (h *Handler) CreateCapsule(c *gin.Context) {
	var req CreateCapsuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}
	if req.UnlockTime.Before(time.Now()) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unlock time must be in the future"})
		return
	}

	if len(req.Message) > MaxMessageBytes {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":      fmt.Sprintf("Message is too long: %d bytes (limit is %d)", len(req.Message), MaxMessageBytes),
			"max_bytes":  MaxMessageBytes,
			"your_bytes": len(req.Message),
		})
		return
	}

	round := h.beacon.TimestampToRound(req.UnlockTime)
	actualUnlockTime := h.beacon.RoundToTimestamp(round)
	ciphertext, err := crypto.Encrypt(h.beacon, []byte(req.Message), round)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt message: " + err.Error()})
		return
	}
	capsule := &storage.Capsule{
		ID:         uuid.New().String(),
		Ciphertext: ciphertext,
		UnlockTime: actualUnlockTime,
		Round:      round,
		Status:     storage.StatusLocked,
		CreatedAt:  time.Now(),
		Metadata:   req.Metadata,
	}

	if err := h.store.SaveCapsule(capsule); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save capsule: " + err.Error()})
		return
	}
	c.JSON(http.StatusCreated, CreateCapsuleResponse{
		CapsuleID:   capsule.ID,
		UnlockTime:  actualUnlockTime,
		RoundNumber: round,
		Status:      string(capsule.Status),
		Ciphertext:  ciphertext,
	})
}
func (h *Handler) GetCapsule(c *gin.Context) {
	id := c.Param("id")

	capsule, err := h.store.GetCapsule(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Capsule not found"})
		return
	}

	response := GetCapsuleResponse{
		CapsuleID:   capsule.ID,
		Status:      string(capsule.Status),
		UnlockTime:  capsule.UnlockTime,
		CreatedAt:   capsule.CreatedAt,
		DecryptedAt: capsule.DecryptedAt,
		Metadata:    capsule.Metadata,
	}
	if capsule.Status == storage.StatusUnlocked && capsule.DecryptedMsg != nil {
		response.Message = string(capsule.DecryptedMsg)
	}

	c.JSON(http.StatusOK, response)
}
func (h *Handler) ListCapsules(c *gin.Context) {
	status := c.Query("status")

	var capsules []*storage.Capsule
	var err error

	if status != "" {
		capsules, err = h.store.GetCapsulesByStatus(storage.CapsuleStatus(status))
	} else {
		locked, _ := h.store.GetCapsulesByStatus(storage.StatusLocked)
		unlocked, _ := h.store.GetCapsulesByStatus(storage.StatusUnlocked)
		failed, _ := h.store.GetCapsulesByStatus(storage.StatusFailed)

		capsules = append(capsules, locked...)
		capsules = append(capsules, unlocked...)
		capsules = append(capsules, failed...)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list capsules"})
		return
	}

	responses := make([]GetCapsuleResponse, 0, len(capsules))
	for _, capsule := range capsules {
		response := GetCapsuleResponse{
			CapsuleID:   capsule.ID,
			Status:      string(capsule.Status),
			UnlockTime:  capsule.UnlockTime,
			CreatedAt:   capsule.CreatedAt,
			DecryptedAt: capsule.DecryptedAt,
			Metadata:    capsule.Metadata,
		}

		if capsule.Status == storage.StatusUnlocked && capsule.DecryptedMsg != nil {
			response.Message = string(capsule.DecryptedMsg)
		}

		responses = append(responses, response)
	}

	c.JSON(http.StatusOK, gin.H{"capsules": responses})
}

func (h *Handler) DeleteCapsule(c *gin.Context) {
	id := c.Param("id")

	if err := h.store.DeleteCapsule(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete capsule"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Capsule deleted successfully"})
}
func (h *Handler) GetStats(c *gin.Context) {
	stats, err := h.store.GetStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get stats"})
		return
	}
	c.JSON(http.StatusOK, stats)
}

func (h *Handler) GetBeaconInfo(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	latestBeacon, err := h.beacon.GetLatestBeacon(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get beacon info"})
		return
	}

	chainInfo := h.beacon.GetChainInfo()

	c.JSON(http.StatusOK, gin.H{
		"latest_round": latestBeacon.Round,
		"latest_time":  latestBeacon.Timestamp,
		"period":       chainInfo.Period.Seconds(),
		"genesis_time": chainInfo.GenesisTime,
	})
}

func (h *Handler) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "healthy",
		"time":   time.Now(),
	})
}

type DecryptRequest struct {
	// Ciphertext is the base64 blob returned by POST /api/capsules. encoding/json
	// decodes a base64 string straight into []byte.
	Ciphertext []byte `json:"ciphertext" binding:"required"`
	// Round is optional. The round is already recorded inside the ciphertext; it
	// is accepted so the API can report the "not yet unlockable" case precisely
	// rather than surfacing a decryption failure.
	Round uint64 `json:"round"`
}

type DecryptResponse struct {
	Message     string    `json:"message"`
	DecryptedAt time.Time `json:"decrypted_at"`
	Round       uint64    `json:"round"`
}

func (h *Handler) DecryptCapsule(c *gin.Context) {
	var req DecryptRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// If the caller told us which round this capsule is for, answer the "not yet"
	// case with the unlock time instead of letting decryption fail obscurely.
	if req.Round > 0 {
		latestBeacon, err := h.beacon.GetLatestBeacon(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get beacon info"})
			return
		}
		if req.Round > latestBeacon.Round {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":          "Beacon round not yet available",
				"current_round":  latestBeacon.Round,
				"required_round": req.Round,
				"unlock_time":    h.beacon.RoundToTimestamp(req.Round),
			})
			return
		}
	}

	plaintext, err := crypto.Decrypt(h.beacon, req.Ciphertext)
	if err != nil {
		log.Printf("Decryption failed for round %d: %v", req.Round, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to decrypt: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, DecryptResponse{
		Message:     string(plaintext),
		DecryptedAt: time.Now(),
		Round:       req.Round,
	})
}
func (h *Handler) GetBeaconSignature(c *gin.Context) {
	var round uint64
	if _, err := fmt.Sscanf(c.Param("round"), "%d", &round); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid round number"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Check if round is available
	latestBeacon, err := h.beacon.GetLatestBeacon(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get beacon info"})
		return
	}

	if round > latestBeacon.Round {
		roundTime := h.beacon.RoundToTimestamp(round)
		c.JSON(http.StatusBadRequest, gin.H{
			"error":         "Round not yet available",
			"current_round": latestBeacon.Round,
			"unlock_time":   roundTime,
		})
		return
	}

	// Fetch beacon value
	beaconValue, err := h.beacon.WaitForRound(ctx, round)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch beacon"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"round":     beaconValue.Round,
		"signature": fmt.Sprintf("%x", beaconValue.Signature),
		"timestamp": beaconValue.Timestamp,
	})
}

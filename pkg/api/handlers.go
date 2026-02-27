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
	CapsuleID   string         `json:"capsule_id"`
	UnlockTime  time.Time      `json:"unlock_time"`
	RoundNumber uint64         `json:"round_number"`
	Status      string         `json:"status"`
	Ciphertext  interface{}    `json:"ciphertext"` //  actual encrypted data
}

type GetCapsuleResponse struct {
	CapsuleID       string    `json:"capsule_id"`
	Status          string    `json:"status"`
	UnlockTime      time.Time `json:"unlock_time"`
	CreatedAt       time.Time `json:"created_at"`
	DecryptedAt     *time.Time `json:"decrypted_at,omitempty"`
	Message         string    `json:"message,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
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

	round := h.beacon.TimestampToRound(req.UnlockTime)
	actualUnlockTime := h.beacon.RoundToTimestamp(round)
	publicKeyPoint := h.beacon.GetPublicKeyPoint()
	scheme := h.beacon.GetScheme()
	ciphertext, err := crypto.Encrypt([]byte(req.Message), round, publicKeyPoint, scheme)
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
		CapsuleID:  capsule.ID,
		Status:     string(capsule.Status),
		UnlockTime: capsule.UnlockTime,
		CreatedAt:  capsule.CreatedAt,
		DecryptedAt: capsule.DecryptedAt,
		Metadata:   capsule.Metadata,
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
			CapsuleID:  capsule.ID,
			Status:     string(capsule.Status),
			UnlockTime: capsule.UnlockTime,
			CreatedAt:  capsule.CreatedAt,
			DecryptedAt: capsule.DecryptedAt,
			Metadata:   capsule.Metadata,
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
	Ciphertext interface{} `json:"ciphertext" binding:"required"`
	Round      uint64      `json:"round" binding:"required"`
}

type DecryptResponse struct {
	Message         string `json:"message"`
	DecryptedAt     time.Time `json:"decrypted_at"`
	Round           uint64 `json:"round"`
	BeaconSignature string `json:"beacon_signature"` //  signature used
}

func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
func (h *Handler) DecryptCapsule(c *gin.Context) {
	var req DecryptRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}
	log.Printf("[DEBUG] Decrypt request - Round: %d, Ciphertext type: %T", req.Round, req.Ciphertext)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	latestBeacon, err := h.beacon.GetLatestBeacon(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get beacon info"})
		return
	}
	if req.Round > latestBeacon.Round {
		roundTime := h.beacon.RoundToTimestamp(req.Round)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Beacon round not yet available",
			"current_round": latestBeacon.Round,
			"required_round": req.Round,
			"unlock_time": roundTime,
		})
		return
	}
	beaconValue, err := h.beacon.WaitForRound(ctx, req.Round)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch beacon signature: " + err.Error()})
		return
	}
	publicKeyPoint := h.beacon.GetPublicKeyPoint()
	scheme := h.beacon.GetScheme()

	if ctMap, ok := req.Ciphertext.(map[string]interface{}); ok {
		log.Printf("[DEBUG] Ciphertext map keys: %v", getMapKeys(ctMap))
		if uVal, hasU := ctMap["u"]; hasU {
			log.Printf("[DEBUG] U field type: %T", uVal)
		}
		if vVal, hasV := ctMap["v"]; hasV {
			log.Printf("[DEBUG] V field type: %T", vVal)
		}
		if wVal, hasW := ctMap["w"]; hasW {
			log.Printf("[DEBUG] W field type: %T", wVal)
		}
	}

	plaintext, err := crypto.Decrypt(req.Ciphertext, beaconValue.Signature, publicKeyPoint, scheme)
	if err != nil {
		log.Printf("[ERROR] Decryption failed for round %d: %v", req.Round, err)
		log.Printf("[ERROR] Beacon signature: %x", beaconValue.Signature)
		log.Printf("[ERROR] Public key: %x", publicKeyPoint)
		log.Printf("[ERROR] Ciphertext type: %T", req.Ciphertext)
		if ctMap, ok := req.Ciphertext.(map[string]interface{}); ok {
			if u, hasU := ctMap["u"]; hasU {
				log.Printf("[ERROR] Ciphertext U type: %T", u)
			}
			if v, hasV := ctMap["v"]; hasV {
				log.Printf("[ERROR] Ciphertext V: %v", v)
			}
			if w, hasW := ctMap["w"]; hasW {
				log.Printf("[ERROR] Ciphertext W: %v", w)
			}
			if ctRound, hasRound := ctMap["round"]; hasRound {
				log.Printf("[ERROR] Ciphertext round field: %v", ctRound)
			}
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt: " + err.Error()})
		return
	}
	log.Printf("[DEBUG] Decryption successful!")

	c.JSON(http.StatusOK, DecryptResponse{
		Message:         string(plaintext),
		DecryptedAt:     time.Now(),
		Round:           req.Round,
		BeaconSignature: fmt.Sprintf("%x", beaconValue.Signature),
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
			"error": "Round not yet available",
			"current_round": latestBeacon.Round,
			"unlock_time": roundTime,
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
		"round": beaconValue.Round,
		"signature": fmt.Sprintf("%x", beaconValue.Signature),
		"timestamp": beaconValue.Timestamp,
	})
}

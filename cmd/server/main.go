package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"timelock-capsule/pkg/api"
	"timelock-capsule/pkg/beacon"
	"timelock-capsule/pkg/crypto"
	"timelock-capsule/pkg/storage"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	port := getEnv("SERVER_PORT", "8080")
	host := getEnv("SERVER_HOST", "localhost")
	dbPath := getEnv("DB_PATH", "./data/capsules.db")
	chainHash := getEnv("DRAND_CHAIN_HASH", "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971") 
	drandURLs := strings.Split(getEnv("DRAND_URLS", "https://api.drand.sh,https://drand.cloudflare.com"), ",")
	if err := os.MkdirAll("./data", 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	// Initialize beacon 
	log.Println("Connecting to drand beacon...")
	beaconClient, err := beacon.NewClient(drandURLs, chainHash)
	if err != nil {
		log.Fatalf("Failed to create beacon client: %v", err)
	}
	defer beaconClient.Close()
	log.Println("Successfully connected to drand beacon")

	// Initialize storage
	log.Println("Initializing storage...")
	store, err := storage.NewStore(dbPath)
	if err != nil {
		log.Fatalf("Failed to create storage: %v", err)
	}
	defer store.Close()
	log.Println("Storage initialized")

	// Initialize API 
	handler := api.NewHandler(store, beaconClient)

	// Start  decryption service
	go startDecryptionService(store, beaconClient)

	// Set up Gin router
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.Default()

	// CORS middleware for development
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// API routes
	apiGroup := router.Group("/api")
	{
		apiGroup.GET("/health", handler.HealthCheck)
		apiGroup.GET("/stats", handler.GetStats)
		apiGroup.GET("/beacon/info", handler.GetBeaconInfo)
		apiGroup.GET("/beacon/signature/:round", handler.GetBeaconSignature)

		// Capsule routes
		apiGroup.POST("/capsules", handler.CreateCapsule)
		apiGroup.GET("/capsules", handler.ListCapsules)
		apiGroup.GET("/capsules/:id", handler.GetCapsule)
		apiGroup.DELETE("/capsules/:id", handler.DeleteCapsule)

		// Decryption route
		apiGroup.POST("/decrypt", handler.DecryptCapsule)
	}

	// Serve static files
	router.Static("/static", "./web/static")
	router.LoadHTMLGlob("./web/templates/*")

	// Serve index page
	router.GET("/", func(c *gin.Context) {
		c.HTML(200, "index.html", gin.H{
			"title": "Time-Locked Message Capsule",
		})
	})

	// Start server
	addr := fmt.Sprintf("%s:%s", host, port)
	log.Printf("Starting server on http://%s", addr)
	log.Printf("API available at http://%s/api", addr)

	if err := router.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func startDecryptionService(store *storage.Store, beaconClient *beacon.Client) {
	// Add panic recovery from chat
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC in decryption service: %v", r)
			log.Printf("Attempting to restart decryption service...")
			time.Sleep(5 * time.Second)
			go startDecryptionService(store, beaconClient)
		}
	}()

	checkInterval := getEnv("DECRYPT_CHECK_INTERVAL", "30s")
	interval, err := time.ParseDuration(checkInterval)
	if err != nil {
		log.Printf("Invalid check interval, using 30s: %v", err)
		interval = 30 * time.Second
	}

	log.Printf("Starting background decryption service (check interval: %s)", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run initial check
	safeProcessDecryptions(store, beaconClient)

	// Continue checking at intervals
	for range ticker.C {
		safeProcessDecryptions(store, beaconClient)
	}
}

// safeProcessDecryptions wraps processDecryptions with panic recovery from chat
func safeProcessDecryptions(store *storage.Store, beaconClient *beacon.Client) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC in processDecryptions: %v", r)
		}
	}()
	processDecryptions(store, beaconClient)
}

func processDecryptions(store *storage.Store, beaconClient *beacon.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
    // Get latest beacon round
	latestBeacon, err := beaconClient.GetLatestBeacon(ctx)
	if err != nil {
		log.Printf("Decryption service: Failed to get latest beacon: %v", err)
		return
	}
	pendingCapsules, err := store.GetPendingCapsules(latestBeacon.Round)
	if err != nil {
		log.Printf("Decryption service: Failed to get pending capsules: %v", err)
		return
	}
	if len(pendingCapsules) == 0 {
		return
	}
	log.Printf("Decryption service: Found %d capsule(s) ready for decryption", len(pendingCapsules))
	for _, capsule := range pendingCapsules {
		decryptCapsule(ctx, store, beaconClient, capsule)
	}
}

func decryptCapsule(ctx context.Context, store *storage.Store, beaconClient *beacon.Client, capsule *storage.Capsule) {
	log.Printf("Decrypting capsule %s (round: %d)", capsule.ID, capsule.Round)
	// Fetch beacon value
	beaconValue, err := beaconClient.WaitForRound(ctx, capsule.Round)
	if err != nil {
		log.Printf("Failed to fetch beacon for capsule %s: %v", capsule.ID, err)
		store.UpdateCapsuleStatus(capsule.ID, storage.StatusFailed, nil)
		return
	}
	publicKeyPoint := beaconClient.GetPublicKeyPoint()
	scheme := beaconClient.GetScheme()

	plaintext, err := crypto.Decrypt(capsule.Ciphertext, beaconValue.Signature, publicKeyPoint, scheme)
	if err != nil {
		log.Printf("Failed to decrypt capsule %s: %v", capsule.ID, err)
		store.UpdateCapsuleStatus(capsule.ID, storage.StatusFailed, nil)
		return
	}
	if err := store.UpdateCapsuleStatus(capsule.ID, storage.StatusUnlocked, plaintext); err != nil {
		log.Printf("Failed to update capsule status %s: %v", capsule.ID, err)
		return
	}

	log.Printf("Successfully decrypted capsule %s", capsule.ID)
}

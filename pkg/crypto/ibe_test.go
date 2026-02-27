package crypto

import (
	"testing"
	"time"

	"github.com/drand/drand/v2/common"
	"github.com/drand/tlock"
	tlockhttp "github.com/drand/tlock/networks/http"
)

// TestEncryptDecryptWithRealDrand tests the complete encryption/decryption flow
// using a real drand beacon signature from the past
func TestEncryptDecryptWithRealDrand(t *testing.T) {
	// Use drand quicknet (unchained) - required for tlock
	// Quicknet is an unchained drand network optimized for timelock encryption
	chainHash := "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

	// Create tlock network client
	network, err := tlockhttp.NewNetwork("https://api.drand.sh", chainHash)
	if err != nil {
		t.Fatalf("Failed to create tlock network: %v", err)
	}

	// Get the public key and scheme from the network
	publicKey := network.PublicKey()
	publicKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	scheme := network.Scheme()
	t.Logf("Using drand public key (length: %d bytes)", len(publicKeyBytes))
	t.Logf("Using scheme: %v", scheme)

	// Get the current round number
	currentRound := network.RoundNumber(time.Now())

	// Use a round from the past (current round minus 10)
	// This ensures the signature is already available
	testRound := currentRound - 10
	t.Logf("Testing with round: %d", testRound)

	// Fetch the beacon signature for this round
	signature, err := network.Signature(testRound)
	if err != nil {
		t.Fatalf("Failed to get signature for round %d: %v", testRound, err)
	}

	t.Logf("Got beacon signature (length: %d bytes)", len(signature))

	// Test message (keep it short - tlock has size limits)
	originalMessage := []byte("Secret message from the past!")
	t.Logf("Original message: %s", string(originalMessage))

	// Encrypt the message using tlock directly
	t.Log("Encrypting message...")
	tlockCiphertext, err := tlock.TimeLock(scheme, publicKey, testRound, originalMessage)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	t.Logf("Encryption successful!")

	// Create a beacon with the signature
	beacon := &common.Beacon{
		Round:     testRound,
		Signature: common.HexBytes(signature),
	}

	// Decrypt the message using tlock directly
	t.Log("Decrypting message...")
	decryptedMessage, err := tlock.TimeUnlock(scheme, publicKey, *beacon, tlockCiphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	t.Logf("Decryption successful!")
	t.Logf("Decrypted message: %s", string(decryptedMessage))

	// Verify the decrypted message matches the original
	if string(decryptedMessage) != string(originalMessage) {
		t.Fatalf("Message mismatch!\nOriginal:  %s\nDecrypted: %s",
			string(originalMessage), string(decryptedMessage))
	}

	t.Log("SUCCESS: Message successfully encrypted and decrypted!")
}

// TestEncryptDecryptWithWrongSignature tests that decryption fails with wrong signature
// This test is now ENABLED - we use proper tlock that validates signatures!
func TestEncryptDecryptWithWrongSignature(t *testing.T) {
	// Use drand quicknet (unchained) - required for tlock
	// Quicknet is an unchained drand network optimized for timelock encryption
	chainHash := "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

	// Create tlock network client
	network, err := tlockhttp.NewNetwork("https://api.drand.sh", chainHash)
	if err != nil {
		t.Fatalf("Failed to create tlock network: %v", err)
	}

	// Get the public key and scheme
	publicKey := network.PublicKey()
	scheme := network.Scheme()

	// Get two different beacon rounds
	currentRound := network.RoundNumber(time.Now())
	round1 := currentRound - 10
	round2 := currentRound - 20

	// Get signature for round2 (the wrong one)
	wrongSignature, err := network.Signature(round2)
	if err != nil {
		t.Fatalf("Failed to get signature for round %d: %v", round2, err)
	}

	// Encrypt with round1
	message := []byte("Secret message")
	ciphertext, err := Encrypt(message, round1, publicKey, scheme)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Try to decrypt with wrong signature (from round2)
	_, err = Decrypt(ciphertext, wrongSignature, publicKey, scheme)
	if err == nil {
		t.Fatal("Expected decryption to fail with wrong signature, but it succeeded!")
	}

	t.Logf("Correctly failed with wrong signature: %v", err)
}

// TestIBEParamsCreation tests that IBE params can be created from drand's public key
func TestIBEParamsCreation(t *testing.T) {
	// Use drand quicknet (unchained) - required for tlock
	// Quicknet is an unchained drand network optimized for timelock encryption
	chainHash := "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

	// Create tlock network client
	network, err := tlockhttp.NewNetwork("https://api.drand.sh", chainHash)
	if err != nil {
		t.Fatalf("Failed to create tlock network: %v", err)
	}

	// Get the public key
	publicKey := network.PublicKey()
	publicKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	// Create IBE params
	params, err := NewIBEParams(publicKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create IBE params: %v", err)
	}

	if params == nil {
		t.Fatal("IBE params is nil")
	}

	if params.Ppub == nil {
		t.Fatal("Ppub is nil")
	}

	if params.G1 == nil || params.G2 == nil || params.GT == nil {
		t.Fatal("Group parameters are nil")
	}

	// Verify that Ppub was correctly unmarshaled
	remarshaled, err := params.Ppub.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to remarshal Ppub: %v", err)
	}

	if len(remarshaled) != len(publicKeyBytes) {
		t.Fatalf("Ppub length mismatch: expected %d, got %d", len(publicKeyBytes), len(remarshaled))
	}

	t.Log("SUCCESS: IBE params created correctly from drand public key")
}

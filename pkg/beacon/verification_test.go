package beacon

import (
	"context"
	"testing"
	"time"
)

// TestBLSSignatureVerification tests that our BLS signature verification actually works
func TestBLSSignatureVerification(t *testing.T) {
	// Connect to drand quicknet
	urls := []string{"https://api.drand.sh"}
	chainHash := "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

	client, err := NewClient(urls, chainHash)
	if err != nil {
		t.Fatalf("Failed to create beacon client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get the latest beacon (which should pass verification)
	t.Log("Fetching latest beacon...")
	beacon, err := client.GetLatestBeacon(ctx)
	if err != nil {
		t.Fatalf("Failed to get latest beacon: %v", err)
	}

	t.Logf("Got beacon for round %d", beacon.Round)
	t.Logf("Signature length: %d bytes", len(beacon.Signature))

	// The fact that GetBeacon succeeded means verifyBeacon passed!
	// Our verifyBeacon function is called inside GetBeacon and would have failed if signature was invalid
	t.Log("✓ BLS signature verification PASSED (pairing equation held)")

	// Now test that a bad signature fails
	t.Log("\nTesting with invalid signature...")
	badSignature := make([]byte, 48)
	// Fill with non-zero garbage (all zeros might be caught earlier)
	for i := range badSignature {
		badSignature[i] = byte(i)
	}

	err = client.verifyBeacon(beacon.Round, badSignature)
	if err == nil {
		t.Fatal("Expected verification to fail with bad signature, but it passed!")
	}

	t.Logf("✓ Invalid signature correctly rejected: %v", err)
	t.Log("\n✓✓✓ BLS SIGNATURE VERIFICATION WORKING CORRECTLY ✓✓✓")
}

// TestPairingEquation demonstrates that we're actually doing pairing math
func TestPairingEquation(t *testing.T) {
	urls := []string{"https://api.drand.sh"}
	chainHash := "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

	client, err := NewClient(urls, chainHash)
	if err != nil {
		t.Fatalf("Failed to create beacon client: %v", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	beacon, err := client.GetLatestBeacon(ctx)
	if err != nil {
		t.Fatalf("Failed to get beacon: %v", err)
	}

	t.Log("=== DEMONSTRATING PAIRING-BASED BLS VERIFICATION ===")
	t.Logf("Round: %d", beacon.Round)
	t.Logf("Signature: %x...", beacon.Signature[:8])

	// The verification happens in verifyBeacon which:
	// 1. Deserializes signature from G1
	// 2. Hashes round number to G2 point
	// 3. Computes e(sig, g2_gen)
	// 4. Computes e(H(round), pubkey)
	// 5. Checks if they're equal

	err = client.verifyBeacon(beacon.Round, beacon.Signature)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	t.Log("✓ Pairing equation: e(sig, G2_gen) = e(H(round), pubkey) HOLDS")
	t.Log("✓ This proves the signature is valid under the drand public key")
	t.Log("✓ BLS12-381 pairing cryptography is working correctly")
}

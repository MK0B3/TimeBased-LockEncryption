package beacon

import (
	"context"
	"testing"
	"time"
)

const (
	testChainHash = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
	testDrandURL  = "https://api.drand.sh"
)

// newTestClient connects to drand quicknet. These tests exercise verification against
// the live network, so they are skipped under -short.
func newTestClient(t *testing.T) *Client {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping test that requires network access to drand")
	}

	client, err := NewClient([]string{testDrandURL}, testChainHash)
	if err != nil {
		t.Fatalf("Failed to create beacon client: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	return client
}

// TestVerifyBeaconAcceptsGenuineSignature checks that a real beacon signature from the
// drand network satisfies the pairing equation under the chain public key.
func TestVerifyBeaconAcceptsGenuineSignature(t *testing.T) {
	client := newTestClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	beacon, err := client.GetLatestBeacon(ctx)
	if err != nil {
		t.Fatalf("Failed to get latest beacon: %v", err)
	}

	if err := client.verifyBeacon(beacon.Round, beacon.Signature); err != nil {
		t.Fatalf("Genuine signature for round %d rejected: %v", beacon.Round, err)
	}
}

// TestVerifyBeaconRejectsSignatureFromAnotherRound is the test that actually pins down
// the pairing check. The signature used here is a genuine drand signature and therefore
// a perfectly well-formed point in the signature group -- it is simply bound to a
// different round. Only a real verification against H(round) can tell the difference,
// so a length or well-formedness check alone would let this through.
func TestVerifyBeaconRejectsSignatureFromAnotherRound(t *testing.T) {
	client := newTestClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	beacon, err := client.GetLatestBeacon(ctx)
	if err != nil {
		t.Fatalf("Failed to get latest beacon: %v", err)
	}

	otherRound := beacon.Round - 10
	otherBeacon, err := client.GetBeacon(ctx, otherRound)
	if err != nil {
		t.Fatalf("Failed to get beacon for round %d: %v", otherRound, err)
	}

	// Valid signature, wrong round: must be rejected.
	if err := client.verifyBeacon(beacon.Round, otherBeacon.Signature); err == nil {
		t.Fatalf("Signature for round %d was accepted for round %d", otherRound, beacon.Round)
	}
}

// TestVerifyBeaconRejectsMalformedSignatures covers the inputs that fail before the
// pairing check is reached.
func TestVerifyBeaconRejectsMalformedSignatures(t *testing.T) {
	client := newTestClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	beacon, err := client.GetLatestBeacon(ctx)
	if err != nil {
		t.Fatalf("Failed to get latest beacon: %v", err)
	}

	garbage := make([]byte, len(beacon.Signature))
	for i := range garbage {
		garbage[i] = byte(i)
	}

	truncated := beacon.Signature[:len(beacon.Signature)-1]

	flipped := make([]byte, len(beacon.Signature))
	copy(flipped, beacon.Signature)
	flipped[len(flipped)-1] ^= 0x01

	tests := []struct {
		name      string
		signature []byte
	}{
		{"empty", nil},
		{"garbage", garbage},
		{"truncated", truncated},
		{"single bit flipped", flipped},
		{"all zeros", make([]byte, len(beacon.Signature))},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := client.verifyBeacon(beacon.Round, tc.signature); err == nil {
				t.Fatalf("Invalid signature (%s) was accepted", tc.name)
			}
		})
	}
}

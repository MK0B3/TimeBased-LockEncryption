package crypto

import (
	"strings"
	"testing"
	"time"

	tlockhttp "github.com/drand/tlock/networks/http"
)

const (
	testChainHash = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
	testDrandURL  = "https://api.drand.sh"
)

// newTestNetwork connects to drand quicknet. These tests exercise encryption
// against the live network, so they are skipped under -short.
func newTestNetwork(t *testing.T) *tlockhttp.Network {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping test that requires network access to drand")
	}

	network, err := tlockhttp.NewNetwork(testDrandURL, testChainHash)
	if err != nil {
		t.Fatalf("Failed to create tlock network: %v", err)
	}

	return network
}

// TestEncryptDecryptRoundTrip checks that a message sealed to a round that has
// already passed can be recovered exactly.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	network := newTestNetwork(t)

	round := network.RoundNumber(time.Now()) - 10
	original := []byte("Secret message from the past!")

	ciphertext, err := Encrypt(network, original, round)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := Decrypt(network, ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(original) {
		t.Fatalf("Message mismatch:\n  original:  %q\n  decrypted: %q", original, decrypted)
	}
}

// TestEncryptAcceptsMessagesBeyondOneHashBlock is the regression test for the
// reason this package moved to tlock's hybrid construction. The raw IBE
// primitive caps plaintext at a single hash block (32 bytes), which rejected
// any realistic message. These sizes all straddle or exceed that boundary.
func TestEncryptAcceptsMessagesBeyondOneHashBlock(t *testing.T) {
	network := newTestNetwork(t)

	round := network.RoundNumber(time.Now()) - 10

	sizes := []int{31, 32, 33, 64, 280, 4096, 64 * 1024}

	for _, size := range sizes {
		original := []byte(strings.Repeat("A", size))

		ciphertext, err := Encrypt(network, original, round)
		if err != nil {
			t.Fatalf("Encryption failed for %d-byte message: %v", size, err)
		}

		decrypted, err := Decrypt(network, ciphertext)
		if err != nil {
			t.Fatalf("Decryption failed for %d-byte message: %v", size, err)
		}

		if string(decrypted) != string(original) {
			t.Fatalf("Round trip corrupted a %d-byte message", size)
		}
	}
}

// TestDecryptFailsBeforeRound checks the core timelock property: a capsule sealed
// to a future round cannot be opened yet, because the signature that unwraps it
// does not exist.
func TestDecryptFailsBeforeRound(t *testing.T) {
	network := newTestNetwork(t)

	futureRound := network.RoundNumber(time.Now().Add(24 * time.Hour))

	ciphertext, err := Encrypt(network, []byte("not yet"), futureRound)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if _, err := Decrypt(network, ciphertext); err == nil {
		t.Fatal("Decrypted a capsule whose round has not been published")
	}
}

// TestDecryptRejectsCorruptedCiphertext checks that tampering is detected rather
// than silently producing garbage.
func TestDecryptRejectsCorruptedCiphertext(t *testing.T) {
	network := newTestNetwork(t)

	round := network.RoundNumber(time.Now()) - 10

	ciphertext, err := Encrypt(network, []byte("tamper with me"), round)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	corrupted := make([]byte, len(ciphertext))
	copy(corrupted, ciphertext)
	corrupted[len(corrupted)-1] ^= 0x01

	if _, err := Decrypt(network, corrupted); err == nil {
		t.Fatal("Decrypted a corrupted ciphertext")
	}
}

// TestEncryptRejectsEmptyInput covers the guard clauses.
func TestEncryptRejectsEmptyInput(t *testing.T) {
	network := newTestNetwork(t)

	if _, err := Encrypt(network, nil, network.RoundNumber(time.Now())); err == nil {
		t.Fatal("Encrypted an empty message")
	}

	if _, err := Decrypt(network, nil); err == nil {
		t.Fatal("Decrypted an empty ciphertext")
	}
}

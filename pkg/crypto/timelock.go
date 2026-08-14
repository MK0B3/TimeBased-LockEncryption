// Package crypto wraps drand's tlock library to seal a message until a chosen
// drand round is published.
package crypto

import (
	"bytes"
	"fmt"

	"github.com/drand/tlock"
)

// Network is the drand network that encryption and decryption run against. It is
// satisfied by *beacon.Client, which verifies every beacon signature it returns.
type Network = tlock.Network

// Encrypt seals message so that it cannot be recovered until the drand network
// publishes the given round.
//
// This uses tlock's hybrid construction: a random symmetric key encrypts the
// message, and only that key is sealed with identity-based encryption against the
// round. Using the IBE primitive directly (tlock.TimeLock) would encrypt the
// message into the pairing group itself, capping it at a single hash block of 32
// bytes -- too small for a real message.
func Encrypt(network Network, message []byte, round uint64) ([]byte, error) {
	if len(message) == 0 {
		return nil, fmt.Errorf("message cannot be empty")
	}

	var buf bytes.Buffer
	if err := tlock.New(network).Encrypt(&buf, bytes.NewReader(message), round); err != nil {
		return nil, fmt.Errorf("timelock encryption failed: %w", err)
	}

	return buf.Bytes(), nil
}

// Decrypt recovers a message sealed by Encrypt. It succeeds only once the round
// named in the ciphertext has been published, because the beacon signature for
// that round is what unwraps the symmetric key.
//
// Strict mode is deliberate: without it tlock would follow a chain hash named
// inside the ciphertext, letting an attacker-supplied ciphertext redirect the
// server to a chain it was never configured to trust.
func Decrypt(network Network, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext cannot be empty")
	}

	var buf bytes.Buffer
	if err := tlock.New(network).Strict().Decrypt(&buf, bytes.NewReader(ciphertext)); err != nil {
		return nil, fmt.Errorf("timelock decryption failed: %w", err)
	}

	return buf.Bytes(), nil
}

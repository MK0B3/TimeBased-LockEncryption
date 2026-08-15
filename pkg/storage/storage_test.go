package storage

import (
	"path/filepath"
	"testing"
	"time"
)

// newTestStore opens a store backed by a throwaway file. These tests touch only
// local disk, so they run under -short.
func newTestStore(t *testing.T) *Store {
	t.Helper()

	store, err := NewStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	return store
}

func newCapsule(id string, round uint64, status CapsuleStatus) *Capsule {
	return &Capsule{
		ID:         id,
		Ciphertext: []byte("ciphertext-for-" + id),
		UnlockTime: time.Now().Add(time.Hour).Truncate(time.Second),
		Round:      round,
		Status:     status,
		CreatedAt:  time.Now().Truncate(time.Second),
	}
}

func TestSaveAndGetCapsule(t *testing.T) {
	store := newTestStore(t)

	original := newCapsule("capsule-1", 100, StatusLocked)
	original.Metadata = map[string]string{"note": "hello"}

	if err := store.SaveCapsule(original); err != nil {
		t.Fatalf("SaveCapsule failed: %v", err)
	}

	loaded, err := store.GetCapsule("capsule-1")
	if err != nil {
		t.Fatalf("GetCapsule failed: %v", err)
	}

	if loaded.ID != original.ID {
		t.Errorf("ID: got %q, want %q", loaded.ID, original.ID)
	}
	if string(loaded.Ciphertext) != string(original.Ciphertext) {
		t.Errorf("Ciphertext: got %q, want %q", loaded.Ciphertext, original.Ciphertext)
	}
	if loaded.Round != original.Round {
		t.Errorf("Round: got %d, want %d", loaded.Round, original.Round)
	}
	if loaded.Status != original.Status {
		t.Errorf("Status: got %q, want %q", loaded.Status, original.Status)
	}
	if loaded.Metadata["note"] != "hello" {
		t.Errorf("Metadata: got %v, want note=hello", loaded.Metadata)
	}
	if !loaded.UnlockTime.Equal(original.UnlockTime) {
		t.Errorf("UnlockTime: got %v, want %v", loaded.UnlockTime, original.UnlockTime)
	}
}

func TestGetCapsuleNotFound(t *testing.T) {
	store := newTestStore(t)

	if _, err := store.GetCapsule("does-not-exist"); err == nil {
		t.Fatal("Expected an error for a missing capsule")
	}
}

func TestUpdateCapsuleStatusUnlocks(t *testing.T) {
	store := newTestStore(t)

	if err := store.SaveCapsule(newCapsule("capsule-1", 100, StatusLocked)); err != nil {
		t.Fatalf("SaveCapsule failed: %v", err)
	}

	plaintext := []byte("the secret")
	if err := store.UpdateCapsuleStatus("capsule-1", StatusUnlocked, plaintext); err != nil {
		t.Fatalf("UpdateCapsuleStatus failed: %v", err)
	}

	loaded, err := store.GetCapsule("capsule-1")
	if err != nil {
		t.Fatalf("GetCapsule failed: %v", err)
	}

	if loaded.Status != StatusUnlocked {
		t.Errorf("Status: got %q, want %q", loaded.Status, StatusUnlocked)
	}
	if string(loaded.DecryptedMsg) != string(plaintext) {
		t.Errorf("DecryptedMsg: got %q, want %q", loaded.DecryptedMsg, plaintext)
	}
	if loaded.DecryptedAt == nil {
		t.Error("DecryptedAt should be set once a capsule unlocks")
	}
}

func TestUpdateCapsuleStatusNotFound(t *testing.T) {
	store := newTestStore(t)

	if err := store.UpdateCapsuleStatus("missing", StatusUnlocked, []byte("x")); err == nil {
		t.Fatal("Expected an error updating a missing capsule")
	}
}

// TestGetPendingCapsulesRespectsRound covers the round index that drives the
// background decryption service: a capsule must not be reported as pending until
// its round has been reached.
func TestGetPendingCapsulesRespectsRound(t *testing.T) {
	store := newTestStore(t)

	for _, c := range []*Capsule{
		newCapsule("past", 100, StatusLocked),
		newCapsule("due", 200, StatusLocked),
		newCapsule("future", 300, StatusLocked),
	} {
		if err := store.SaveCapsule(c); err != nil {
			t.Fatalf("SaveCapsule failed: %v", err)
		}
	}

	pending, err := store.GetPendingCapsules(200)
	if err != nil {
		t.Fatalf("GetPendingCapsules failed: %v", err)
	}

	got := map[string]bool{}
	for _, c := range pending {
		got[c.ID] = true
	}

	if !got["past"] || !got["due"] {
		t.Errorf("Expected past and due to be pending at round 200, got %v", got)
	}
	if got["future"] {
		t.Error("Capsule at round 300 must not be pending at round 200")
	}
}

// TestGetPendingCapsulesExcludesUnlocked checks that a capsule leaves the pending
// set once it has been decrypted, so the service does not reprocess it forever.
func TestGetPendingCapsulesExcludesUnlocked(t *testing.T) {
	store := newTestStore(t)

	if err := store.SaveCapsule(newCapsule("capsule-1", 100, StatusLocked)); err != nil {
		t.Fatalf("SaveCapsule failed: %v", err)
	}

	pending, err := store.GetPendingCapsules(150)
	if err != nil {
		t.Fatalf("GetPendingCapsules failed: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("Expected 1 pending capsule before unlocking, got %d", len(pending))
	}

	if err := store.UpdateCapsuleStatus("capsule-1", StatusUnlocked, []byte("done")); err != nil {
		t.Fatalf("UpdateCapsuleStatus failed: %v", err)
	}

	pending, err = store.GetPendingCapsules(150)
	if err != nil {
		t.Fatalf("GetPendingCapsules failed: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("Expected no pending capsules after unlocking, got %d", len(pending))
	}
}

func TestGetCapsulesByStatus(t *testing.T) {
	store := newTestStore(t)

	for _, c := range []*Capsule{
		newCapsule("locked-1", 100, StatusLocked),
		newCapsule("locked-2", 101, StatusLocked),
		newCapsule("failed-1", 102, StatusFailed),
	} {
		if err := store.SaveCapsule(c); err != nil {
			t.Fatalf("SaveCapsule failed: %v", err)
		}
	}

	locked, err := store.GetCapsulesByStatus(StatusLocked)
	if err != nil {
		t.Fatalf("GetCapsulesByStatus failed: %v", err)
	}
	if len(locked) != 2 {
		t.Errorf("Expected 2 locked capsules, got %d", len(locked))
	}

	unlocked, err := store.GetCapsulesByStatus(StatusUnlocked)
	if err != nil {
		t.Fatalf("GetCapsulesByStatus failed: %v", err)
	}
	if len(unlocked) != 0 {
		t.Errorf("Expected 0 unlocked capsules, got %d", len(unlocked))
	}
}

func TestDeleteCapsule(t *testing.T) {
	store := newTestStore(t)

	if err := store.SaveCapsule(newCapsule("capsule-1", 100, StatusLocked)); err != nil {
		t.Fatalf("SaveCapsule failed: %v", err)
	}

	if err := store.DeleteCapsule("capsule-1"); err != nil {
		t.Fatalf("DeleteCapsule failed: %v", err)
	}

	if _, err := store.GetCapsule("capsule-1"); err == nil {
		t.Fatal("Capsule should be gone after deletion")
	}

	// A deleted capsule must also leave the round index, or the decryption
	// service would keep trying to load a capsule that no longer exists.
	pending, err := store.GetPendingCapsules(150)
	if err != nil {
		t.Fatalf("GetPendingCapsules failed: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("Expected no pending capsules after deletion, got %d", len(pending))
	}
}

func TestGetStats(t *testing.T) {
	store := newTestStore(t)

	for _, c := range []*Capsule{
		newCapsule("locked-1", 100, StatusLocked),
		newCapsule("locked-2", 101, StatusLocked),
		newCapsule("failed-1", 102, StatusFailed),
	} {
		if err := store.SaveCapsule(c); err != nil {
			t.Fatalf("SaveCapsule failed: %v", err)
		}
	}
	if err := store.UpdateCapsuleStatus("locked-2", StatusUnlocked, []byte("x")); err != nil {
		t.Fatalf("UpdateCapsuleStatus failed: %v", err)
	}

	stats, err := store.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	want := map[string]int{"total": 3, "locked": 1, "unlocked": 1, "failed": 1}
	for key, expected := range want {
		if stats[key] != expected {
			t.Errorf("stats[%q]: got %d, want %d", key, stats[key], expected)
		}
	}
}

// TestCapsulesPersistAcrossReopen checks that data survives a restart, which is
// the whole reason the capsules live in BoltDB rather than in memory.
func TestCapsulesPersistAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persist.db")

	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	if err := store.SaveCapsule(newCapsule("capsule-1", 100, StatusLocked)); err != nil {
		t.Fatalf("SaveCapsule failed: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	reopened, err := NewStore(path)
	if err != nil {
		t.Fatalf("Failed to reopen store: %v", err)
	}
	defer reopened.Close()

	loaded, err := reopened.GetCapsule("capsule-1")
	if err != nil {
		t.Fatalf("GetCapsule after reopen failed: %v", err)
	}
	if string(loaded.Ciphertext) != "ciphertext-for-capsule-1" {
		t.Errorf("Ciphertext did not survive reopen: got %q", loaded.Ciphertext)
	}
}

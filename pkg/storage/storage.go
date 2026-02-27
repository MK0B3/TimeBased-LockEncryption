package storage

import (
	"encoding/json"
	"fmt"
	"time"

	"timelock-capsule/pkg/crypto"

	bolt "go.etcd.io/bbolt"
)

var (
	capsulesBucket = []byte("capsules")
	indexBucket    = []byte("index")
)

type Capsule struct {
	ID             string                  `json:"id"`
	Ciphertext     *crypto.IBECiphertext   `json:"ciphertext"`
	UnlockTime     time.Time               `json:"unlock_time"`
	Round          uint64                  `json:"round"`
	Status         CapsuleStatus           `json:"status"`
	DecryptedMsg   []byte                  `json:"decrypted_message,omitempty"`
	CreatedAt      time.Time               `json:"created_at"`
	DecryptedAt    *time.Time              `json:"decrypted_at,omitempty"`
	Metadata       map[string]string       `json:"metadata,omitempty"`
}

type CapsuleStatus string

const (
	StatusLocked   CapsuleStatus = "locked"
	StatusUnlocked CapsuleStatus = "unlocked"
	StatusFailed   CapsuleStatus = "failed"
)

type Store struct {
	db *bolt.DB
}

func NewStore(dbPath string) (*Store, error) {
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(capsulesBucket); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(indexBucket); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create buckets: %w", err)
	}

	return &Store{db: db}, nil
}

func (s *Store) SaveCapsule(capsule *Capsule) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(capsulesBucket)

		data, err := json.Marshal(capsule)
		if err != nil {
			return fmt.Errorf("failed to marshal capsule: %w", err)
		}

		if err := b.Put([]byte(capsule.ID), data); err != nil {
			return fmt.Errorf("failed to save capsule: %w", err)
		}

		if capsule.Status == StatusLocked {
			idx := tx.Bucket(indexBucket)
			roundKey := fmt.Sprintf("round:%020d:%s", capsule.Round, capsule.ID)
			if err := idx.Put([]byte(roundKey), []byte(capsule.ID)); err != nil {
				return fmt.Errorf("failed to update index: %w", err)
			}
		}

		return nil
	})
}

func (s *Store) GetCapsule(id string) (*Capsule, error) {
	var capsule Capsule

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(capsulesBucket)
		data := b.Get([]byte(id))
		if data == nil {
			return fmt.Errorf("capsule not found")
		}

		return json.Unmarshal(data, &capsule)
	})

	if err != nil {
		return nil, err
	}

	return &capsule, nil
}

func (s *Store) UpdateCapsuleStatus(id string, status CapsuleStatus, decryptedMsg []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(capsulesBucket)
		idx := tx.Bucket(indexBucket)

		data := b.Get([]byte(id))
		if data == nil {
			return fmt.Errorf("capsule not found")
		}

		var capsule Capsule
		if err := json.Unmarshal(data, &capsule); err != nil {
			return err
		}

		if capsule.Status == StatusLocked && status != StatusLocked {
			roundKey := fmt.Sprintf("round:%020d:%s", capsule.Round, capsule.ID)
			idx.Delete([]byte(roundKey))
		}

		capsule.Status = status
		if status == StatusUnlocked && decryptedMsg != nil {
			capsule.DecryptedMsg = decryptedMsg
			now := time.Now()
			capsule.DecryptedAt = &now
		}

		updatedData, err := json.Marshal(capsule)
		if err != nil {
			return err
		}

		return b.Put([]byte(id), updatedData)
	})
}

func (s *Store) GetPendingCapsules(beforeRound uint64) ([]*Capsule, error) {
	var capsules []*Capsule

	err := s.db.View(func(tx *bolt.Tx) error {
		idx := tx.Bucket(indexBucket)
		b := tx.Bucket(capsulesBucket)

		c := idx.Cursor()

		minKey := []byte(fmt.Sprintf("round:%020d:", 0))
		maxKey := []byte(fmt.Sprintf("round:%020d:", beforeRound+1))

		for k, v := c.Seek(minKey); k != nil && string(k) < string(maxKey); k, v = c.Next() {
			capsuleData := b.Get(v)
			if capsuleData == nil {
				continue
			}

			var capsule Capsule
			if err := json.Unmarshal(capsuleData, &capsule); err != nil {
				return err
			}

			if capsule.Status == StatusLocked && capsule.Round <= beforeRound {
				capsules = append(capsules, &capsule)
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return capsules, nil
}

func (s *Store) GetCapsulesByStatus(status CapsuleStatus) ([]*Capsule, error) {
	var capsules []*Capsule

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(capsulesBucket)

		return b.ForEach(func(k, v []byte) error {
			var capsule Capsule
			if err := json.Unmarshal(v, &capsule); err != nil {
				return err
			}

			if capsule.Status == status {
				capsules = append(capsules, &capsule)
			}

			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	return capsules, nil
}

func (s *Store) DeleteCapsule(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(capsulesBucket)
		idx := tx.Bucket(indexBucket)

		data := b.Get([]byte(id))
		if data != nil {
			var capsule Capsule
			if err := json.Unmarshal(data, &capsule); err == nil {
				if capsule.Status == StatusLocked {
					roundKey := fmt.Sprintf("round:%020d:%s", capsule.Round, capsule.ID)
					idx.Delete([]byte(roundKey))
				}
			}
		}

		return b.Delete([]byte(id))
	})
}

func (s *Store) GetStats() (map[string]int, error) {
	stats := map[string]int{
		"total":    0,
		"locked":   0,
		"unlocked": 0,
		"failed":   0,
	}

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(capsulesBucket)

		return b.ForEach(func(k, v []byte) error {
			stats["total"]++

			var capsule Capsule
			if err := json.Unmarshal(v, &capsule); err != nil {
				return err
			}

			switch capsule.Status {
			case StatusLocked:
				stats["locked"]++
			case StatusUnlocked:
				stats["unlocked"]++
			case StatusFailed:
				stats["failed"]++
			}

			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	return stats, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}
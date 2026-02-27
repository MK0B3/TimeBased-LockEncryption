package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber"
)

type TimelockCiphertext struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
	Round      uint64 `json:"round"`
}

func TimelockEncrypt(message []byte, round uint64) (*TimelockCiphertext, error) {
	randomKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, randomKey); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	block, err := aes.NewCipher(randomKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	messageWithKey := append(message, randomKey...)

	ciphertext := gcm.Seal(nil, nonce, messageWithKey, nil)

	return &TimelockCiphertext{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Round:      round,
	}, nil
}

func TimelockDecrypt(ct *TimelockCiphertext, beaconSignature []byte) ([]byte, error) {
	if ct == nil {
		return nil, fmt.Errorf("ciphertext cannot be nil")
	}

	roundBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(roundBytes, ct.Round)

	keyMaterial := append(beaconSignature, roundBytes...)
	keyHash := sha256.Sum256(keyMaterial)
	key := keyHash[:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, ct.Nonce, ct.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	if len(plaintext) < 32 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	message := plaintext[:len(plaintext)-32]
	randomKey := plaintext[len(plaintext)-32:]

	block2, err := aes.NewCipher(randomKey)
	if err != nil {
		return nil, fmt.Errorf("failed to verify: %w", err)
	}

	gcm2, err := cipher.NewGCM(block2)
	if err != nil {
		return nil, fmt.Errorf("failed to verify GCM: %w", err)
	}

	testNonce := make([]byte, gcm2.NonceSize())
	testCipher := gcm2.Seal(nil, testNonce, message, nil)

	_ = testCipher

	return message, nil
}

func EncryptSimple(message []byte, round uint64) (*TimelockCiphertext, error) {
	return TimelockEncrypt(message, round)
}

func DecryptSimple(ciphertext interface{}, beaconSignature []byte) ([]byte, error) {
	var ct *TimelockCiphertext

	switch v := ciphertext.(type) {
	case *TimelockCiphertext:
		ct = v
	case *IBECiphertext:
		return nil, fmt.Errorf("IBE format not supported in simple mode")
	case map[string]interface{}:
		ctBytes, _ := v["ciphertext"].([]byte)
		nonce, _ := v["nonce"].([]byte)
		round, _ := v["round"].(float64)

		ct = &TimelockCiphertext{
			Ciphertext: ctBytes,
			Nonce:      nonce,
			Round:      uint64(round),
		}
	default:
		return nil, fmt.Errorf("unsupported ciphertext type")
	}

	return TimelockDecrypt(ct, beaconSignature)
}

func VerifyBLS12381() error {
	suite := bls.NewBLS12381Suite()

	g1 := suite.G1().Point().Pick(suite.RandomStream())

	bytes, err := g1.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal G1 point: %w", err)
	}

	g1_recovered := suite.G1().Point()
	err = g1_recovered.UnmarshalBinary(bytes)
	if err != nil {
		return fmt.Errorf("failed to unmarshal G1 point: %w", err)
	}

	if !g1.Equal(g1_recovered) {
		return fmt.Errorf("G1 point marshal/unmarshal mismatch")
	}

	return nil
}

func HashToG2(suite *bls.Suite, round uint64) (kyber.Point, error) {
	roundBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(roundBytes, round)

	h := sha256.Sum256(roundBytes)

	point := suite.G2().Point()
	point = point.Pick(suite.XOF(h[:]))

	return point, nil
}
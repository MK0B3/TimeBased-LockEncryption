package crypto

import (
	"encoding/base64"
	"fmt"

	"github.com/drand/drand/v2/common"
	"github.com/drand/drand/v2/crypto"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/encrypt/ibe"
	"github.com/drand/tlock"
)

type IBECiphertext struct {
	U     []byte `json:"u"`
	V     []byte `json:"v"`
	W     []byte `json:"w"`
	Round uint64 `json:"round"`
	Nonce []byte `json:"nonce"`
	Qid   []byte `json:"qid"`
}

type IBEParams struct {
	G1   kyber.Group
	G2   kyber.Group
	GT   kyber.Group
	P    kyber.Point
	Ppub kyber.Point
}

func NewIBEParams(publicKeyBytes []byte) (*IBEParams, error) {
	suite := bls.NewBLS12381Suite()

	var ppub kyber.Point
	var err error

	if len(publicKeyBytes) == 48 {
		ppub = suite.G1().Point()
		err = ppub.UnmarshalBinary(publicKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal G1 public key: %w", err)
		}
	} else if len(publicKeyBytes) == 96 {
		ppub = suite.G2().Point()
		err = ppub.UnmarshalBinary(publicKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal G2 public key: %w", err)
		}
	} else {
		return nil, fmt.Errorf("invalid public key length: %d bytes (expected 48 or 96)", len(publicKeyBytes))
	}

	return &IBEParams{
		G1:   suite.G1(),
		G2:   suite.G2(),
		GT:   suite.GT(),
		P:    suite.G2().Point().Base(),
		Ppub: ppub,
	}, nil
}

func IBEEncrypt(params *IBEParams, identity uint64, message []byte, scheme crypto.Scheme) (*IBECiphertext, error) {
	if params == nil {
		return nil, fmt.Errorf("IBE params cannot be nil")
	}

	if len(message) == 0 {
		return nil, fmt.Errorf("message cannot be empty")
	}

	ciphertext, err := tlock.TimeLock(scheme, params.Ppub, identity, message)
	if err != nil {
		return nil, fmt.Errorf("tlock encryption failed: %w", err)
	}

	ctBytes, err := tlock.CiphertextToBytes(scheme, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ciphertext: %w", err)
	}

	return &IBECiphertext{
		U:     ctBytes,
		V:     nil,
		Round: identity,
		Nonce: nil,
		Qid:   nil,
	}, nil
}

func IBEDecrypt(params *IBEParams, ct *IBECiphertext, privateKey []byte, scheme crypto.Scheme) ([]byte, error) {
	if params == nil {
		return nil, fmt.Errorf("IBE params cannot be nil")
	}

	if ct == nil {
		return nil, fmt.Errorf("ciphertext cannot be nil")
	}

	if len(privateKey) == 0 {
		return nil, fmt.Errorf("private key (beacon signature) cannot be empty")
	}

	ciphertext, err := tlock.BytesToCiphertext(scheme, ct.U)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize ciphertext: %w", err)
	}

	beacon := &common.Beacon{
		Round:       ct.Round,
		Signature:   common.HexBytes(privateKey),
		PreviousSig: nil,
	}

	plaintext, err := tlock.TimeUnlock(scheme, params.Ppub, *beacon, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("tlock decryption failed (wrong signature or corrupted data): %w", err)
	}

	return plaintext, nil
}

func Encrypt(message []byte, round uint64, drandPublicKey kyber.Point, scheme crypto.Scheme) (*IBECiphertext, error) {
	if drandPublicKey == nil {
		return nil, fmt.Errorf("drand public key cannot be nil")
	}

	if len(message) == 0 {
		return nil, fmt.Errorf("message cannot be empty")
	}

	ciphertext, err := tlock.TimeLock(scheme, drandPublicKey, round, message)
	if err != nil {
		return nil, fmt.Errorf("tlock encryption failed: %w", err)
	}

	uBytes, err := ciphertext.U.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal U: %w", err)
	}

	return &IBECiphertext{
		U:     uBytes,
		V:     ciphertext.V,
		W:     ciphertext.W,
		Round: round,
		Nonce: nil,
		Qid:   nil,
	}, nil
}

func Decrypt(ciphertext interface{}, beaconSignature []byte, drandPublicKey kyber.Point, scheme crypto.Scheme) ([]byte, error) {
	var ct *IBECiphertext

	switch v := ciphertext.(type) {
	case *IBECiphertext:
		ct = v
	case map[string]interface{}:
		var u, vBytes, w []byte
		var round uint64
		var err error

		if uStr, ok := v["u"].(string); ok {
			u, err = base64.StdEncoding.DecodeString(uStr)
			if err != nil {
				return nil, fmt.Errorf("failed to decode U: %w", err)
			}
		} else if uBytesRaw, ok := v["u"].([]byte); ok {
			u = uBytesRaw
		}

		if vStr, ok := v["v"].(string); ok {
			vBytes, err = base64.StdEncoding.DecodeString(vStr)
			if err != nil {
				return nil, fmt.Errorf("failed to decode V: %w", err)
			}
		} else if vBytesRaw, ok := v["v"].([]byte); ok {
			vBytes = vBytesRaw
		}

		if wStr, ok := v["w"].(string); ok {
			w, err = base64.StdEncoding.DecodeString(wStr)
			if err != nil {
				return nil, fmt.Errorf("failed to decode W: %w", err)
			}
		} else if wBytesRaw, ok := v["w"].([]byte); ok {
			w = wBytesRaw
		}

		if roundFloat, ok := v["round"].(float64); ok {
			round = uint64(roundFloat)
		} else if roundInt, ok := v["round"].(uint64); ok {
			round = roundInt
		}

		ct = &IBECiphertext{
			U:     u,
			V:     vBytes,
			W:     w,
			Round: round,
		}
	default:
		return nil, fmt.Errorf("unsupported ciphertext type")
	}

	if drandPublicKey == nil {
		return nil, fmt.Errorf("drand public key cannot be nil")
	}

	var tlockCiphertext *ibe.Ciphertext
	var err error

	if ct.V == nil && ct.W == nil {
		tlockCiphertext, err = tlock.BytesToCiphertext(scheme, ct.U)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize ciphertext from U field: %w", err)
		}
	} else {
		var ct2 ibe.Ciphertext

		ct2.U = scheme.KeyGroup.Point()
		if err := ct2.U.UnmarshalBinary(ct.U); err != nil {
			return nil, fmt.Errorf("failed to unmarshal U: %w", err)
		}

		ct2.V = ct.V
		ct2.W = ct.W
		tlockCiphertext = &ct2
	}

	beacon := common.Beacon{
		Round:     ct.Round,
		Signature: common.HexBytes(beaconSignature),
	}

	plaintext, err := tlock.TimeUnlock(scheme, drandPublicKey, beacon, tlockCiphertext)
	if err != nil {
		return nil, fmt.Errorf("tlock decryption failed (wrong signature or corrupted data): %w", err)
	}

	return plaintext, nil
}
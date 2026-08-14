// Package tpmwork defines the consensus-facing TPM work-signature format.
//
// Ethereum account keys remain secp256k1 keys. A work signer is a separate
// ECDSA P-256 key whose private component is expected to be non-exportable and
// held by a TPM. Signatures are encoded as fixed-width r || s values.
package tpmwork

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
)

const (
	DigestSize    = 32
	PublicKeySize = 65
	SignatureSize = 64
)

// Signer supplies one TPM-authorized signature for one consensus work digest.
type Signer interface {
	PublicKey() []byte
	SignDigest(digest []byte) ([]byte, error)
	Close() error
}

// PrivateExportProbe is implemented by backends that can test the provider's
// private-key export policy without returning private key material.
type PrivateExportProbe interface {
	PrivateKeyExportBlocked() (blocked bool, status uint32)
	PrivateKeyExportPolicy() (uint32, error)
}

// ParsePublicKey parses the uncompressed SEC1 encoding of a P-256 public key.
func ParsePublicKey(encoded []byte) (*ecdsa.PublicKey, error) {
	if len(encoded) != PublicKeySize || encoded[0] != 4 {
		return nil, fmt.Errorf("tpmwork: public key must be a %d-byte uncompressed P-256 key", PublicKeySize)
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), encoded)
	if x == nil || y == nil {
		return nil, errors.New("tpmwork: invalid P-256 public key")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// VerifyDigest verifies a fixed-width TPM work signature over a 32-byte digest.
func VerifyDigest(publicKey, digest, signature []byte) bool {
	if len(digest) != DigestSize || len(signature) != SignatureSize {
		return false
	}
	pub, err := ParsePublicKey(publicKey)
	if err != nil {
		return false
	}
	r := new(big.Int).SetBytes(signature[:SignatureSize/2])
	s := new(big.Int).SetBytes(signature[SignatureSize/2:])
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	// Reject the ECDSA (r, N-s) twin. Without this rule one TPM signature
	// could be transformed into a second valid ECCPoW input off device.
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)
	if s.Cmp(halfOrder) > 0 {
		return false
	}
	return ecdsa.Verify(pub, digest, r, s)
}

// NormalizeSignature converts a raw P-256 signature to canonical low-s form.
func NormalizeSignature(signature []byte) ([]byte, error) {
	if len(signature) != SignatureSize {
		return nil, fmt.Errorf("tpmwork: signature must be %d bytes", SignatureSize)
	}
	out := append([]byte(nil), signature...)
	s := new(big.Int).SetBytes(out[SignatureSize/2:])
	order := elliptic.P256().Params().N
	if s.Sign() <= 0 || s.Cmp(order) >= 0 {
		return nil, errors.New("tpmwork: P-256 signature s is out of range")
	}
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(order), 1)
	if s.Cmp(halfOrder) > 0 {
		s.Sub(order, s)
		s.FillBytes(out[SignatureSize/2:])
	}
	return out, nil
}

//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vct

import (
	"crypto/sha256"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/crypto"
	secp256k1pkg "github.com/cryptoecc/WorldLand/crypto/secp256k1"
)

// DeriveVRFKeys derives a deterministic secp256k1 VRF key pair from a coinbase address
// and an optional node key (e.g. the p2p node's secp256k1 private key bytes).
// Returns seckey (32 bytes) and compressed pubkey (33 bytes).
func DeriveVRFKeys(coinbase common.Address, nodeKey []byte) (seckey, pubkey []byte, err error) {
	h := sha256.New()
	h.Write([]byte("WorldLand secp256k1 VRF key derivation v1"))
	h.Write(coinbase.Bytes())
	if len(nodeKey) > 0 {
		h.Write(nodeKey)
	}
	seed := h.Sum(nil) // 32 bytes

	// Iterate until we have a valid secp256k1 scalar (negligible loop count in practice)
	for {
		privKey, kerr := crypto.ToECDSA(seed)
		if kerr == nil {
			seckey = make([]byte, 32)
			blob := privKey.D.Bytes()
			copy(seckey[32-len(blob):], blob)
			pubkey = secp256k1pkg.CompressPubkey(privKey.X, privKey.Y)
			return seckey, pubkey, nil
		}
		next := sha256.Sum256(seed)
		seed = next[:]
	}
}

// VRFPubkeyFromSeckey derives the 33-byte compressed secp256k1 public key from a 32-byte private key.
func VRFPubkeyFromSeckey(seckey []byte) ([]byte, error) {
	privKey, err := crypto.ToECDSA(seckey)
	if err != nil {
		return nil, err
	}
	return secp256k1pkg.CompressPubkey(privKey.X, privKey.Y), nil
}

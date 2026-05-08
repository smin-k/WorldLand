//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vct

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"

	secp256k1pkg "github.com/cryptoecc/WorldLand/crypto/secp256k1"
)

// makeTestKeypair returns a 32-byte seckey and 33-byte compressed pubkey for secp256k1.
func makeTestKeypair(t *testing.T) (seckey, pubkey []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(secp256k1pkg.S256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seckey = make([]byte, 32)
	blob := key.D.Bytes()
	copy(seckey[32-len(blob):], blob)
	full := elliptic.Marshal(secp256k1pkg.S256(), key.X, key.Y)
	pubkey = secp256k1pkg.CompressPubkey(
		new(big.Int).SetBytes(full[1:33]),
		new(big.Int).SetBytes(full[33:65]),
	)
	return
}

func TestVCTVRFProveVerify(t *testing.T) {
	seckey, pubkey := makeTestKeypair(t)
	msg := []byte("VCT_VRF|91510|parenthash|42")

	proof, output, err := VRFProve(seckey, pubkey, msg)
	if err != nil {
		t.Fatalf("VRFProve failed: %v", err)
	}
	if len(proof) != 81 {
		t.Fatalf("proof length wrong: got %d, want 81", len(proof))
	}

	got, err := VRFVerify(pubkey, proof, msg)
	if err != nil {
		t.Fatalf("VRFVerify failed: %v", err)
	}
	if !bytes.Equal(output[:], got[:]) {
		t.Fatalf("VRF output mismatch: prove=%x verify=%x", output, got)
	}
}

func TestVCTVRFDeriveKeys(t *testing.T) {
	from := [20]byte{1, 2, 3, 4, 5}
	seckey, pubkey, err := secp256k1pkg.DeriveVRFKeys(from, nil)
	if err != nil {
		t.Fatalf("secp256k1pkg.DeriveVRFKeys failed: %v", err)
	}
	if len(seckey) != 32 {
		t.Fatalf("seckey length wrong: got %d", len(seckey))
	}
	if len(pubkey) != 33 {
		t.Fatalf("pubkey length wrong: got %d", len(pubkey))
	}

	// Derived keys must be deterministic
	seckey2, pubkey2, err := secp256k1pkg.DeriveVRFKeys(from, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(seckey, seckey2) || !bytes.Equal(pubkey, pubkey2) {
		t.Fatal("secp256k1pkg.DeriveVRFKeys is not deterministic")
	}
}

func TestVCTCheckSortition(t *testing.T) {
	seckey, pubkey := makeTestKeypair(t)
	msg := []byte("sortition seed")

	proof, _, err := VRFProve(seckey, pubkey, msg)
	if err != nil {
		t.Fatal(err)
	}

	// Just check it doesn't panic and returns a bool
	result := CheckSortition(proof)
	t.Logf("sortition result: %v (first byte = 0x%02x)", result, proof[0])
}

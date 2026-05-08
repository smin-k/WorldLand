// Copyright 2024 The WorldLand Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package secp256k1

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
)

// makeVRFKeypair returns a 32-byte private key and its 33-byte compressed public key.
func makeVRFKeypair(t *testing.T) (seckey, pubkey []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(S256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seckey = make([]byte, 32)
	blob := key.D.Bytes()
	copy(seckey[32-len(blob):], blob)

	full := elliptic.Marshal(S256(), key.X, key.Y) // 65-byte uncompressed
	pubkey = CompressPubkey(
		new(big.Int).SetBytes(full[1:33]),
		new(big.Int).SetBytes(full[33:65]),
	)
	return seckey, pubkey
}

func TestVRFProveAndVerify(t *testing.T) {
	seckey, pubkey := makeVRFKeypair(t)
	msg := []byte("VCT_VRF|worldland|testhash|42")

	proof, output, err := VRFProve(seckey, pubkey, msg)
	if err != nil {
		t.Fatalf("VRFProve failed: %v", err)
	}

	verified, err := VRFVerify(pubkey, proof, msg)
	if err != nil {
		t.Fatalf("VRFVerify failed: %v", err)
	}

	if !bytes.Equal(output[:], verified[:]) {
		t.Fatalf("VRF output mismatch: prove=%x verify=%x", output, verified)
	}
	t.Logf("VRF output: %x", output)
}

func TestVRFDeterministic(t *testing.T) {
	seckey, pubkey := makeVRFKeypair(t)
	msg := []byte("same message")

	_, out1, err := VRFProve(seckey, pubkey, msg)
	if err != nil {
		t.Fatal(err)
	}
	_, out2, err := VRFProve(seckey, pubkey, msg)
	if err != nil {
		t.Fatal(err)
	}
	if out1 != out2 {
		t.Fatal("VRF output is not deterministic for the same (key, msg)")
	}
}

func TestVRFDifferentMessages(t *testing.T) {
	seckey, pubkey := makeVRFKeypair(t)

	_, out1, _ := VRFProve(seckey, pubkey, []byte("message-A"))
	_, out2, _ := VRFProve(seckey, pubkey, []byte("message-B"))

	if out1 == out2 {
		t.Fatal("VRF outputs must differ for different messages")
	}
}

func TestVRFDifferentKeys(t *testing.T) {
	sk1, pk1 := makeVRFKeypair(t)
	sk2, pk2 := makeVRFKeypair(t)
	msg := []byte("same message")

	_, out1, _ := VRFProve(sk1, pk1, msg)
	_, out2, _ := VRFProve(sk2, pk2, msg)

	if out1 == out2 {
		t.Fatal("VRF outputs must differ for different keys")
	}
}

func TestVRFWrongKeyVerify(t *testing.T) {
	seckey, pubkey := makeVRFKeypair(t)
	_, wrongPubkey := makeVRFKeypair(t)
	msg := []byte("test message")

	proof, _, err := VRFProve(seckey, pubkey, msg)
	if err != nil {
		t.Fatal(err)
	}

	_, err = VRFVerify(wrongPubkey, proof, msg)
	if err == nil {
		t.Fatal("VRFVerify should fail with wrong public key")
	}
}

func TestVRFProofToHash(t *testing.T) {
	seckey, pubkey := makeVRFKeypair(t)
	msg := []byte("test")

	proof, output, err := VRFProve(seckey, pubkey, msg)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := VRFProofToHash(proof)
	if err != nil {
		t.Fatalf("VRFProofToHash failed: %v", err)
	}
	if hash != output {
		t.Fatalf("ProofToHash mismatch: %x vs %x", hash, output)
	}
}

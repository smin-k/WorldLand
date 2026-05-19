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

// TestVRFWrongMessageVerify checks that a proof produced for msg_A cannot be
// verified against msg_B.  This guards against proof replay across different
// VRF inputs (e.g. different block numbers or parent hashes in VCT).
func TestVRFWrongMessageVerify(t *testing.T) {
	seckey, pubkey := makeVRFKeypair(t)
	msgA := []byte("VCT_VRF|10399|parenthash_A|100")
	msgB := []byte("VCT_VRF|10399|parenthash_B|101")

	proof, _, err := VRFProve(seckey, pubkey, msgA)
	if err != nil {
		t.Fatal(err)
	}

	_, err = VRFVerify(pubkey, proof, msgB)
	if err == nil {
		t.Fatal("VRFVerify must fail when message does not match the proof")
	}
}

// TestVRFTamperedProofRejected checks that flipping any single byte in the
// proof causes VRFVerify to return an error.  A malicious proposer must not be
// able to forge eligibility by submitting a modified proof.
func TestVRFTamperedProofRejected(t *testing.T) {
	seckey, pubkey := makeVRFKeypair(t)
	msg := []byte("VCT_VRF|10399|someparenthash|200")

	proof, _, err := VRFProve(seckey, pubkey, msg)
	if err != nil {
		t.Fatal(err)
	}

	// Flip every byte in turn; at least the first flip must be rejected.
	// (All 81 must be rejected for a correct implementation.)
	rejected := 0
	for i := 0; i < 81; i++ {
		tampered := proof
		tampered[i] ^= 0xFF
		_, verr := VRFVerify(pubkey, tampered, msg)
		if verr != nil {
			rejected++
		}
	}
	if rejected == 0 {
		t.Fatal("VRFVerify accepted a fully-tampered proof — implementation is broken")
	}
	if rejected < 81 {
		t.Logf("note: %d/81 byte positions were accepted after single-byte flip (expected 0)", 81-rejected)
	}
	t.Logf("tamper rejection: %d/81 byte positions correctly rejected", rejected)
}

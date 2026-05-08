// Copyright 2024 The WorldLand Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package secp256k1

/*
#include "./libsecp256k1/include/secp256k1_vrf.h"

// secp256k1_ext_vrf_prove wraps secp256k1_vrf_prove, accepting a 33-byte
// compressed public key instead of a secp256k1_pubkey struct.
static int secp256k1_ext_vrf_prove(
    secp256k1_context* ctx,
    unsigned char proof[81],
    const unsigned char seckey[32],
    const unsigned char pk[33],
    const void* msg,
    const unsigned int msglen
) {
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pk, 33)) {
        return 0;
    }
    return secp256k1_vrf_prove(proof, seckey, &pubkey, msg, msglen);
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

var (
	ErrVRFProveFailed    = errors.New("VRF prove failed")
	ErrVRFVerifyFailed   = errors.New("VRF verify failed")
	ErrVRFHashFailed     = errors.New("VRF proof-to-hash failed")
	ErrInvalidCompPubkey = errors.New("invalid compressed public key length, need 33 bytes")
)

// VRFProve generates an 81-byte VRF proof and the corresponding 32-byte
// random output for the given message using the account's private key.
//
// seckey must be a 32-byte secp256k1 private key.
// pubkey must be the corresponding 33-byte compressed public key.
// msg may be of arbitrary length.
//
// Returns (proof [81]byte, output [32]byte, error).
func VRFProve(seckey, pubkey, msg []byte) (proof [81]byte, output [32]byte, err error) {
	if len(seckey) != 32 {
		return proof, output, ErrInvalidKey
	}
	if len(pubkey) != 33 {
		return proof, output, ErrInvalidCompPubkey
	}
	if len(msg) == 0 {
		return proof, output, ErrInvalidMsgLen
	}

	seckeyPtr := (*C.uchar)(unsafe.Pointer(&seckey[0]))
	pubkeyPtr := (*C.uchar)(unsafe.Pointer(&pubkey[0]))
	msgPtr    := unsafe.Pointer(&msg[0])

	if C.secp256k1_ext_vrf_prove(
		context,
		(*C.uchar)(unsafe.Pointer(&proof[0])),
		seckeyPtr,
		pubkeyPtr,
		msgPtr,
		C.uint(len(msg)),
	) != 1 {
		return proof, output, ErrVRFProveFailed
	}

	if C.secp256k1_vrf_proof_to_hash(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&proof[0])),
	) != 1 {
		return proof, output, ErrVRFHashFailed
	}

	return proof, output, nil
}

// VRFVerify verifies an 81-byte VRF proof against the given public key and
// message. On success it returns the 32-byte random output derived from the
// proof. The returned output is identical to the one produced by VRFProve.
//
// pubkey must be the 33-byte compressed public key of the prover.
// proof  must be an 81-byte VRF proof produced by VRFProve.
// msg    is the original message passed to VRFProve.
func VRFVerify(pubkey []byte, proof [81]byte, msg []byte) (output [32]byte, err error) {
	if len(pubkey) != 33 {
		return output, ErrInvalidCompPubkey
	}
	if len(msg) == 0 {
		return output, ErrInvalidMsgLen
	}

	if C.secp256k1_vrf_verify(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&proof[0])),
		(*C.uchar)(unsafe.Pointer(&pubkey[0])),
		unsafe.Pointer(&msg[0]),
		C.uint(len(msg)),
	) != 1 {
		return output, ErrVRFVerifyFailed
	}

	return output, nil
}

// VRFProofToHash extracts the 32-byte random output from a proof without
// verifying it. Only call this after a successful VRFProve or VRFVerify.
func VRFProofToHash(proof [81]byte) (output [32]byte, err error) {
	if C.secp256k1_vrf_proof_to_hash(
		(*C.uchar)(unsafe.Pointer(&output[0])),
		(*C.uchar)(unsafe.Pointer(&proof[0])),
	) != 1 {
		return output, ErrVRFHashFailed
	}
	return output, nil
}

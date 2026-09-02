//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vct

import (
	"errors"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/crypto/tpmwork"
)

// TPMWorkMessage returns the canonical digest that a registered TPM work key
// authorizes for one chain, candidate template, identity, VRF output and nonce.
// It is exported so an untrusted delegated worker protocol can transport the
// exact consensus input without introducing a second, worker-local nonce.
func TPMWorkMessage(chainIDBytes, sealHash []byte, did common.Hash, vrfOutput [32]byte, nonce uint64) []byte {
	return computeTPMWorkSigMsg(chainIDBytes, sealHash, did, vrfOutput, nonce)
}

// DelegatedWorkEvaluator evaluates canonical TPM-authorized ECCVCC attempts.
// Its precomputed decoding matrices are immutable after construction, so one
// evaluator can be shared by concurrent delegated-worker handlers.
type DelegatedWorkEvaluator struct {
	header        *types.Header
	workPublicKey []byte
	parameters    Parameters
	h             [][]int
	colInRow      [][]int
	rowInCol      [][]int
}

// NewDelegatedWorkEvaluator prepares the consensus puzzle for a candidate
// header and the registered TPM work public key.
func NewDelegatedWorkEvaluator(header *types.Header, workPublicKey []byte) (*DelegatedWorkEvaluator, error) {
	if header == nil || header.Difficulty == nil || header.Difficulty.Sign() <= 0 {
		return nil, errors.New("VCT: delegated evaluator requires a positive-difficulty header")
	}
	if _, err := tpmwork.ParsePublicKey(workPublicKey); err != nil {
		return nil, err
	}
	parameters, _ := setParameters(header)
	h := generateH(parameters)
	colInRow, rowInCol := generateQ(parameters, h)
	return &DelegatedWorkEvaluator{
		header: types.CopyHeader(header), workPublicKey: append([]byte(nil), workPublicKey...),
		parameters: parameters, h: h, colInRow: colInRow, rowInCol: rowInCol,
	}, nil
}

// Evaluate verifies that the TPM authorized workMessage and then executes the
// same ECCVCC decoding and decision path used by the local VCT miner.
func (e *DelegatedWorkEvaluator) Evaluate(workMessage, signature []byte) (bool, error) {
	if e == nil {
		return false, errors.New("VCT: nil delegated evaluator")
	}
	if !tpmwork.VerifyDigest(e.workPublicKey, workMessage, signature) {
		return false, errors.New("VCT: invalid delegated TPM work signature")
	}
	powSeed := computeTPMPowSeed(workMessage, signature)
	digest := crypto.Keccak512(powSeed)
	hv := generateHv(e.parameters, digest)
	_, outputWord, _ := OptimizedDecoding(e.parameters, hv, e.h, e.rowInCol, e.colInRow)
	success, _ := MakeDecision(e.header, e.colInRow, outputWord)
	return success, nil
}

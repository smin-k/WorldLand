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

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/crypto/secp256k1"
	"github.com/cryptoecc/WorldLand/crypto/tpmwork"
	"github.com/cryptoecc/WorldLand/rlp"
	"golang.org/x/crypto/sha3"
)

func TestTPMWorkMessageBindsEveryConsensusInput(t *testing.T) {
	chainID := make([]byte, 32)
	chainID[31] = 1
	sealHash := make([]byte, 32)
	sealHash[31] = 2
	did := common.HexToHash("0x03")
	var vrfOutput [32]byte
	vrfOutput[31] = 4

	base := computeTPMWorkSigMsg(chainID, sealHash, did, vrfOutput, 5)
	cases := [][]byte{
		computeTPMWorkSigMsg(chainID, sealHash, did, vrfOutput, 6),
		computeTPMWorkSigMsg(chainID, sealHash, common.HexToHash("0x07"), vrfOutput, 5),
		computeTPMWorkSigMsg(chainID, append(make([]byte, 31), 8), did, vrfOutput, 5),
	}
	for i, other := range cases {
		if string(base) == string(other) {
			t.Fatalf("case %d did not change TPM work message", i)
		}
	}
}

func TestAbsentTPMFieldsPreserveLegacyVCTSealHash(t *testing.T) {
	ecc := NewFaker()
	ecc.chainID = big.NewInt(91510)
	header := &types.Header{
		ParentHash:           common.HexToHash("0x01"),
		Coinbase:             common.HexToAddress("0x02"),
		Difficulty:           big.NewInt(3),
		Number:               big.NewInt(4),
		Time:                 5,
		Extra:                []byte{6},
		VRFPublicKey:         []byte{7},
		EligibilityThreshold: big.NewInt(8),
		BaseFee:              big.NewInt(9),
	}
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write([]byte("VCT_SEAL"))
	hasher.Write(ecc.chainIDBytes())
	legacyFields := []interface{}{
		header.ParentHash, header.UncleHash, header.Coinbase,
		header.Root, header.TxHash, header.ReceiptHash,
		header.Bloom, header.Difficulty, header.Number,
		header.GasLimit, header.GasUsed, header.Time, header.Extra,
		header.VRFPublicKey, header.EligibilityThreshold, header.BaseFee,
	}
	if err := rlp.Encode(hasher, legacyFields); err != nil {
		t.Fatal(err)
	}
	expected := hasher.Sum(nil)
	if got := ecc.SealHash(header).Bytes(); !bytes.Equal(got, expected) {
		t.Fatalf("pre-TPM VCT seal hash changed: got %x want %x", got, expected)
	}
}

func TestVerifyTPMWorkSignatureEndToEnd(t *testing.T) {
	ecc := NewFaker()
	ecc.chainID = big.NewInt(91510)
	seckey := make([]byte, 32)
	seckey[31] = 1
	vrfPublicKey, err := secp256k1.VRFPubkeyFromSeckey(seckey)
	if err != nil {
		t.Fatal(err)
	}
	header := &types.Header{
		ParentHash:           common.HexToHash("0x1234"),
		Coinbase:             common.HexToAddress("0x5678"),
		Difficulty:           big.NewInt(65536),
		Number:               big.NewInt(42),
		EligibilityThreshold: new(big.Int).Set(EligibilityThresholdMax),
		VRFPublicKey:         vrfPublicKey,
		TPMDID:               common.HexToHash("0x99").Bytes(),
		Nonce:                types.EncodeNonce(7),
	}
	vrfMessage := computeVRFMsg(ecc.chainIDBytes(), header.ParentHash.Bytes(), header.Number.Uint64())
	proof, vrfOutput, err := VRFProve(seckey, vrfPublicKey, vrfMessage)
	if err != nil {
		t.Fatal(err)
	}
	header.VRFProof = proof

	workKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	header.TPMWorkPublicKey = elliptic.Marshal(elliptic.P256(), workKey.X, workKey.Y)
	sealHash := ecc.SealHash(header).Bytes()
	workMessage := computeTPMWorkSigMsg(ecc.chainIDBytes(), sealHash, common.BytesToHash(header.TPMDID), vrfOutput, header.Nonce.Uint64())
	r, s, err := ecdsa.Sign(rand.Reader, workKey, workMessage)
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, tpmwork.SignatureSize)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	header.TPMWorkSignature, err = tpmwork.NormalizeSignature(signature)
	if err != nil {
		t.Fatal(err)
	}
	if err := ecc.verifyTPMWorkSig(header, sealHash); err != nil {
		t.Fatalf("valid TPM work signature rejected: %v", err)
	}

	mutated := types.CopyHeader(header)
	mutated.Nonce = types.EncodeNonce(8)
	if err := ecc.verifyTPMWorkSig(mutated, sealHash); err == nil {
		t.Fatal("TPM work signature reused for a different nonce")
	}
}

func TestTPMWorkSignatureProducesCanonicalPowInput(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := make([]byte, tpmwork.DigestSize)
	message[0] = 1
	r, s, err := ecdsa.Sign(rand.Reader, key, message)
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, tpmwork.SignatureSize)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	signature, err = tpmwork.NormalizeSignature(signature)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	if !tpmwork.VerifyDigest(publicKey, message, signature) {
		t.Fatal("valid TPM work signature rejected")
	}
	seed := computeTPMPowSeed(message, signature)
	modified := append([]byte(nil), signature...)
	modified[0] ^= 1
	if string(seed) == string(computeTPMPowSeed(message, modified)) {
		t.Fatal("signature was not committed to ECCPoW input")
	}
}

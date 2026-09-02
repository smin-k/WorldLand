package tpmregistry

import (
	"math/big"
	"testing"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/crypto"
)

func TestApprovalDigestAndRecovery(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	chainID := big.NewInt(103)
	registry := common.HexToAddress("0x801")
	controller := common.HexToAddress("0x1234")
	nullifier := crypto.Keccak256Hash([]byte("canonical EK Name"))
	statement := EnrollmentStatement{
		RequestID:       DeriveRequestID(registry, chainID, controller, big.NewInt(7)),
		DID:             DeriveDID(chainID, registry, nullifier),
		Controller:      controller,
		WorkKeyHash:     crypto.Keccak256Hash([]byte("work key")),
		VRFKeyHash:      crypto.Keccak256Hash([]byte("VRF key")),
		ProfileHash:     crypto.Keccak256Hash([]byte("TPM profile")),
		DeviceNullifier: nullifier,
		PolicyDigest:    crypto.Keccak256Hash([]byte("validator policy")),
		EvidenceHash:    crypto.Keccak256Hash([]byte("evidence bundle")),
		ValidatorEpoch:  3,
		Deadline:        900,
	}
	digest := ApprovalDigest(chainID, registry, statement)
	signature, err := crypto.Sign(digest[:], key)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := RecoverApprovalSigner(digest, signature)
	if err != nil {
		t.Fatal(err)
	}
	want := crypto.PubkeyToAddress(key.PublicKey)
	if signer != want {
		t.Fatalf("recovered signer %s, want %s", signer, want)
	}

	signature[crypto.RecoveryIDOffset] += 27
	signer, err = RecoverApprovalSigner(digest, signature)
	if err != nil || signer != want {
		t.Fatalf("27/28 signature recovery: signer %s, error %v", signer, err)
	}
}

func TestApprovalBindsRegistrationContext(t *testing.T) {
	chainID := big.NewInt(103)
	registry := common.HexToAddress("0x801")
	nullifier := crypto.Keccak256Hash([]byte("EK Name"))
	statement := EnrollmentStatement{
		RequestID:       common.HexToHash("0x01"),
		DID:             DeriveDID(chainID, registry, nullifier),
		Controller:      common.HexToAddress("0x1234"),
		WorkKeyHash:     common.HexToHash("0x02"),
		VRFKeyHash:      common.HexToHash("0x03"),
		ProfileHash:     common.HexToHash("0x04"),
		DeviceNullifier: nullifier,
		PolicyDigest:    common.HexToHash("0x05"),
		EvidenceHash:    common.HexToHash("0x06"),
		ValidatorEpoch:  1,
		Deadline:        100,
	}
	original := ApprovalDigest(chainID, registry, statement)

	statement.EvidenceHash = common.HexToHash("0x07")
	if ApprovalDigest(chainID, registry, statement) == original {
		t.Fatal("evidence mutation did not change approval digest")
	}
	if DeriveDID(big.NewInt(104), registry, nullifier) == statement.DID {
		t.Fatal("DID was not separated by chain ID")
	}
	if DeriveDID(chainID, common.HexToAddress("0x802"), nullifier) == statement.DID {
		t.Fatal("DID was not separated by registry address")
	}
}

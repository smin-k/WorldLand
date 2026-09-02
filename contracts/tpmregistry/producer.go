package tpmregistry

import (
	"fmt"
	"math/big"

	"github.com/cryptoecc/WorldLand/accounts/abi"
	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/crypto"
)

var (
	producerEnrollmentTypeHash = crypto.Keccak256Hash([]byte("ProducerEnrollment(bytes32 requestId,bytes32 identity,address controller,bytes32 workKeyHash,bytes32 vrfKeyHash,bytes32 profileHash,bytes32 deviceNullifier,bytes32 policyDigest,bytes32 evidenceHash,uint64 firstSlot,uint64 lastSlot,uint64 responseDeadline)"))
	producerChallengeDomain    = crypto.Keccak256Hash([]byte("WorldLand TGPoW producer challenge v1"))
	producerApprovalDomain     = crypto.Keccak256Hash([]byte("WorldLand TGPoW producer approval v1"))
	producerCertifyDomain      = crypto.Keccak256Hash([]byte("WorldLand TGPoW certify challenge v1"))
)

// ProducerEnrollmentStatement is frozen when the controller opens a dynamic
// block-producer enrollment. Identity is the legacy ABI name for the
// chain-scoped TPM-bound consensus identity.
type ProducerEnrollmentStatement struct {
	RequestID        common.Hash
	Identity         common.Hash
	Controller       common.Address
	WorkKeyHash      common.Hash
	VRFKeyHash       common.Hash
	ProfileHash      common.Hash
	DeviceNullifier  common.Hash
	PolicyDigest     common.Hash
	EvidenceHash     common.Hash
	FirstSlot        uint64
	LastSlot         uint64
	ResponseDeadline uint64
}

func (s ProducerEnrollmentStatement) StructHash() common.Hash {
	return crypto.Keccak256Hash(encodeWords(
		producerEnrollmentTypeHash[:], s.RequestID[:], s.Identity[:], s.Controller[:],
		s.WorkKeyHash[:], s.VRFKeyHash[:], s.ProfileHash[:], s.DeviceNullifier[:],
		s.PolicyDigest[:], s.EvidenceHash[:], uint64Word(s.FirstSlot),
		uint64Word(s.LastSlot), uint64Word(s.ResponseDeadline),
	))
}

// CredentialHash commits to the exact MakeCredential credentialBlob and
// encryptedSecret using Solidity's abi.encode(bytes,bytes) representation.
func CredentialHash(credentialBlob, encryptedSecret []byte) (common.Hash, error) {
	bytesType, err := abi.NewType("bytes", "", nil)
	if err != nil {
		return common.Hash{}, err
	}
	encoded, err := (abi.Arguments{{Type: bytesType}, {Type: bytesType}}).Pack(credentialBlob, encryptedSecret)
	if err != nil {
		return common.Hash{}, fmt.Errorf("tpmregistry: encode credential material: %w", err)
	}
	return crypto.Keccak256Hash(encoded), nil
}

func ProducerChallengeCommitment(
	chainID *big.Int,
	registry common.Address,
	requestID, statementHash common.Hash,
	slot uint64,
	producer common.Address,
	credentialHash, secret common.Hash,
) common.Hash {
	return crypto.Keccak256Hash(encodeWords(
		producerChallengeDomain[:], chainID.Bytes(), registry[:], requestID[:], statementHash[:],
		uint64Word(slot), producer[:], credentialHash[:], secret[:],
	))
}

// ProducerChallengeDigest is signed by the designated slot producer and
// checked against block.coinbase when the challenge is included.
func ProducerChallengeDigest(
	chainID *big.Int,
	registry common.Address,
	requestID common.Hash,
	slot uint64,
	producer common.Address,
	credentialHash, commitment common.Hash,
) common.Hash {
	return crypto.Keccak256Hash(encodeWords(
		producerChallengeDomain[:], chainID.Bytes(), registry[:], requestID[:],
		uint64Word(slot), producer[:], credentialHash[:], commitment[:],
	))
}

// ProducerApprovalDigest is signed only after the producer validates the
// TPM2_Certify evidence committed by evidenceHash.
func ProducerApprovalDigest(
	chainID *big.Int,
	registry common.Address,
	requestID common.Hash,
	slot uint64,
	commitment, evidenceHash, identity common.Hash,
	deadline uint64,
) common.Hash {
	return crypto.Keccak256Hash(encodeWords(
		producerApprovalDomain[:], chainID.Bytes(), registry[:], requestID[:], uint64Word(slot),
		commitment[:], evidenceHash[:], identity[:], uint64Word(deadline),
	))
}

func ProducerCertifyChallenge(chainID *big.Int, registry common.Address, requestID common.Hash, slot uint64, commitment common.Hash) common.Hash {
	return crypto.Keccak256Hash(encodeWords(
		producerCertifyDomain[:], chainID.Bytes(), registry[:], requestID[:], uint64Word(slot), commitment[:],
	))
}

func uint64Word(value uint64) []byte {
	return new(big.Int).SetUint64(value).Bytes()
}

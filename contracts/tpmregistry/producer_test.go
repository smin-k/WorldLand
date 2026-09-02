package tpmregistry

import (
	"math/big"
	"testing"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/crypto/tpmwork"
)

func TestProducerHashesBindSlotAndEvidence(t *testing.T) {
	chainID := big.NewInt(103)
	registry := common.HexToAddress("0x801")
	requestID := crypto.Keccak256Hash([]byte("request"))
	statementHash := crypto.Keccak256Hash([]byte("statement"))
	producer := common.HexToAddress("0x1234")
	credentialHash, err := CredentialHash([]byte("credential blob"), []byte("encrypted secret"))
	if err != nil {
		t.Fatal(err)
	}
	secret := crypto.Keccak256Hash([]byte("ActivateCredential output"))
	commitment := ProducerChallengeCommitment(
		chainID, registry, requestID, statementHash, 42, producer, credentialHash, secret,
	)
	if commitment == ProducerChallengeCommitment(chainID, registry, requestID, statementHash, 43, producer, credentialHash, secret) {
		t.Fatal("challenge commitment did not bind the block slot")
	}
	if commitment == ProducerChallengeCommitment(chainID, registry, requestID, statementHash, 42, producer, credentialHash, common.HexToHash("0x01")) {
		t.Fatal("challenge commitment did not bind the recovered secret")
	}

	evidenceOne := crypto.Keccak256Hash([]byte("certify evidence one"))
	evidenceTwo := crypto.Keccak256Hash([]byte("certify evidence two"))
	identity := crypto.Keccak256Hash([]byte("consensus identity"))
	digestOne := ProducerApprovalDigest(chainID, registry, requestID, 42, commitment, evidenceOne, identity, 100)
	digestTwo := ProducerApprovalDigest(chainID, registry, requestID, 42, commitment, evidenceTwo, identity, 100)
	if digestOne == digestTwo {
		t.Fatal("producer approval did not bind Certify evidence")
	}
}

func TestProducerSignatureRecovery(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	producer := crypto.PubkeyToAddress(key.PublicKey)
	digest := ProducerChallengeDigest(
		big.NewInt(103), common.HexToAddress("0x801"), common.HexToHash("0x01"),
		7, producer, common.HexToHash("0x02"), common.HexToHash("0x03"),
	)
	signature, err := crypto.Sign(digest[:], key)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := RecoverApprovalSigner(digest, signature)
	if err != nil || recovered != producer {
		t.Fatalf("recovered producer %s, want %s, error %v", recovered, producer, err)
	}
}

func TestProducerCertifyChallengeBindsContext(t *testing.T) {
	chainID := big.NewInt(103)
	registry := common.HexToAddress("0x801")
	request := common.HexToHash("0x01")
	commitment := common.HexToHash("0x02")
	original := ProducerCertifyChallenge(chainID, registry, request, 7, commitment)
	if original == ProducerCertifyChallenge(chainID, registry, request, 8, commitment) {
		t.Fatal("certify challenge did not bind slot")
	}
	if original == ProducerCertifyChallenge(chainID, registry, request, 7, common.HexToHash("0x03")) {
		t.Fatal("certify challenge did not bind commitment")
	}
}

func TestProducerResponseEvidenceCanonicalRoundTrip(t *testing.T) {
	original := &ProducerResponseEvidence{
		Version: ProducerEvidenceVersion,
		WorkCertification: tpmwork.KeyCertification{
			Version: tpmwork.CertificationVersion, Challenge: []byte("challenge"),
			WorkPublicKey: []byte("work"), WorkPublicArea: []byte("work-area"),
			AttestationPublicKey: []byte("ak"), AttestationPublicArea: []byte("ak-area"),
			AttestationStatement: []byte("statement"), AttestationSignature: []byte("signature"),
		},
	}
	encoded, err := original.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeProducerResponseEvidence(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded.WorkCertification.Challenge) != "challenge" || ProducerEvidenceHash(encoded) == (common.Hash{}) {
		t.Fatalf("unexpected decoded evidence: %+v", decoded)
	}
}

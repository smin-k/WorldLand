package tpmregistry

import (
	"crypto/subtle"
	"errors"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/crypto/tpmwork"
	"github.com/cryptoecc/WorldLand/rlp"
)

const ProducerEvidenceVersion = 1

// ProducerResponseEvidence is the canonical evidence disclosed for one
// producer slot after ActivateCredential succeeds.
type ProducerResponseEvidence struct {
	Version           uint32
	WorkCertification tpmwork.KeyCertification
}

func (e *ProducerResponseEvidence) CanonicalBytes() ([]byte, error) {
	if e == nil || e.Version != ProducerEvidenceVersion {
		return nil, errors.New("tpmregistry: invalid producer evidence version")
	}
	return rlp.EncodeToBytes(e)
}

func DecodeProducerResponseEvidence(encoded []byte) (*ProducerResponseEvidence, error) {
	var evidence ProducerResponseEvidence
	if len(encoded) == 0 {
		return nil, errors.New("tpmregistry: empty producer evidence")
	}
	if err := rlp.DecodeBytes(encoded, &evidence); err != nil {
		return nil, err
	}
	if evidence.Version != ProducerEvidenceVersion {
		return nil, errors.New("tpmregistry: unsupported producer evidence version")
	}
	return &evidence, nil
}

func ProducerEvidenceHash(encoded []byte) common.Hash {
	return crypto.Keccak256Hash(encoded)
}

// VerifyProducerResponseEvidence validates TPM2_Certify and binds its AK/work
// keys and deterministic freshness challenge to the original enrollment.
func VerifyProducerResponseEvidence(initial *Evidence, expectedChallenge []byte, encoded []byte) error {
	if initial == nil {
		return errors.New("tpmregistry: missing enrollment evidence")
	}
	evidence, err := DecodeProducerResponseEvidence(encoded)
	if err != nil {
		return err
	}
	certification := &evidence.WorkCertification
	if subtle.ConstantTimeCompare(certification.Challenge, expectedChallenge) != 1 {
		return errors.New("tpmregistry: producer certification challenge mismatch")
	}
	if err := tpmwork.VerifyKeyCertification(certification); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(certification.WorkPublicKey, initial.WorkPublicKey) != 1 ||
		subtle.ConstantTimeCompare(certification.AttestationPublicKey, initial.AttestationPublicKey) != 1 ||
		subtle.ConstantTimeCompare(certification.AttestationPublicArea, initial.AttestationPublicArea) != 1 {
		return errors.New("tpmregistry: producer certification keys differ from enrollment")
	}
	return nil
}

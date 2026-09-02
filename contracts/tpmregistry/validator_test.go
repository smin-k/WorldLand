package tpmregistry

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/cryptoecc/WorldLand/common"
	worldcrypto "github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/crypto/tpmwork"
)

func TestValidatorChallengeApproval(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	root, _ := x509.ParseCertificate(rootDER)
	ekKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ekTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "EK"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour),
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{ekCertificateOID},
	}
	ekDER, _ := x509.CreateCertificate(rand.Reader, ekTemplate, root, &ekKey.PublicKey, rootKey)
	attestationKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	attestationDER, _ := x509.MarshalPKIXPublicKey(&attestationKey.PublicKey)
	workKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	vrfKey, _ := worldcrypto.GenerateKey()
	profile := []byte("test-profile")
	evidence := Evidence{
		Version: EvidenceVersion, EKCertificateDER: ekDER,
		EKPublicArea:          marshalRSAEnrollmentPublic(&ekKey.PublicKey, true),
		AttestationPublicKey:  attestationDER,
		AttestationPublicArea: marshalRSAEnrollmentPublic(&attestationKey.PublicKey, false),
		WorkPublicKey:         elliptic.Marshal(elliptic.P256(), workKey.X, workKey.Y),
		VRFPublicKey:          worldcrypto.FromECDSAPub(&vrfKey.PublicKey), Profile: profile,
	}
	policy := &Policy{
		Version: EvidenceVersion, RootCertificates: []*x509.Certificate{root},
		RequireEKCertificateOID: true, MaxEvidenceBytes: 1 << 20,
		AllowedProfileHashes: []common.Hash{worldcrypto.Keccak256Hash(profile)}, Clock: func() time.Time { return now },
	}
	chainID := big.NewInt(103)
	registry := common.HexToAddress("0x801")
	validated, err := policy.ValidateEvidence(chainID, registry, &evidence)
	if err != nil {
		t.Fatal(err)
	}
	policyDigest, _ := policy.Digest()
	controller := common.HexToAddress("0x1234")
	statement := EnrollmentStatement{
		RequestID: common.HexToHash("0x01"), DID: validated.DID, Controller: controller,
		WorkKeyHash: validated.WorkKeyHash, VRFKeyHash: validated.VRFKeyHash,
		ProfileHash: validated.ProfileHash, DeviceNullifier: validated.DeviceNullifier,
		PolicyDigest: policyDigest, EvidenceHash: validated.EvidenceHash,
		ValidatorEpoch: 1, Deadline: 100,
	}
	validatorKey, _ := worldcrypto.GenerateKey()
	service, err := NewValidatorService(ValidatorConfig{
		ChainID: chainID, Registry: registry, Policy: policy, SigningKey: validatorKey,
		AllowUnverifiedRequest: true, SessionTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := service.Challenge(context.Background(), ChallengeRequest{Statement: statement, Evidence: evidence})
	if err != nil {
		t.Fatal(err)
	}
	service.mu.Lock()
	activatedSecret := append([]byte(nil), service.sessions[challenge.SessionID].secret...)
	service.mu.Unlock()
	certification := makeValidatorCertification(t, workKey, attestationKey, evidence.AttestationPublicArea, evidence.AttestationPublicKey, challenge.CertifyChallenge)
	approval, err := service.Approve(context.Background(), ApprovalRequest{
		SessionID: challenge.SessionID, ActivatedSecret: activatedSecret, WorkCertification: certification,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := ApprovalDigest(chainID, registry, statement)
	signer, err := RecoverApprovalSigner(digest, approval.Signature)
	if err != nil || signer != service.Address() {
		t.Fatalf("approval signer %s, error %v", signer, err)
	}
	if _, err := service.Approve(context.Background(), ApprovalRequest{SessionID: challenge.SessionID}); err == nil {
		t.Fatal("one-shot validator session was reused")
	}
}

func makeValidatorCertification(t *testing.T, workKey *ecdsa.PrivateKey, attestationKey *rsa.PrivateKey, attestationArea, attestationDER, challenge []byte) tpmwork.KeyCertification {
	t.Helper()
	workArea := marshalECCWorkPublic(&workKey.PublicKey)
	_, workName, err := tpmwork.ParsePublicArea(workArea)
	if err != nil {
		t.Fatal(err)
	}
	_, attestationName, err := tpmwork.ParsePublicArea(attestationArea)
	if err != nil {
		t.Fatal(err)
	}
	var statement bytes.Buffer
	_ = binary.Write(&statement, binary.BigEndian, uint32(0xff544347))
	writeEnrollmentU16(&statement, 0x8017)
	writeEnrollmentTPM2B(&statement, attestationName)
	writeEnrollmentTPM2B(&statement, challenge)
	statement.Write(make([]byte, 25)) // TPMS_CLOCK_INFO and firmwareVersion
	writeEnrollmentTPM2B(&statement, workName)
	writeEnrollmentTPM2B(&statement, workName)
	digest := sha256.Sum256(statement.Bytes())
	signature, err := rsa.SignPKCS1v15(rand.Reader, attestationKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	var encodedSignature bytes.Buffer
	writeEnrollmentU16(&encodedSignature, 0x0014)
	writeEnrollmentU16(&encodedSignature, 0x000b)
	writeEnrollmentTPM2B(&encodedSignature, signature)
	return tpmwork.KeyCertification{
		Version: tpmwork.CertificationVersion, Challenge: challenge,
		WorkPublicKey:  elliptic.Marshal(elliptic.P256(), workKey.X, workKey.Y),
		WorkPublicArea: workArea, AttestationPublicKey: attestationDER,
		AttestationPublicArea: attestationArea, AttestationStatement: statement.Bytes(),
		AttestationSignature: encodedSignature.Bytes(),
	}
}

func marshalECCWorkPublic(public *ecdsa.PublicKey) []byte {
	attributes := uint32(tpmwork.ObjectFixedTPM | tpmwork.ObjectFixedParent | tpmwork.ObjectSensitiveDataOrigin | tpmwork.ObjectSignEncrypt)
	var area bytes.Buffer
	writeEnrollmentU16(&area, 0x0023) // TPM_ALG_ECC
	writeEnrollmentU16(&area, 0x000b) // TPM_ALG_SHA256
	_ = binary.Write(&area, binary.BigEndian, attributes)
	writeEnrollmentTPM2B(&area, nil)
	writeEnrollmentU16(&area, 0x0010) // symmetric: null
	writeEnrollmentU16(&area, 0x0010) // scheme: null
	writeEnrollmentU16(&area, 0x0003) // NIST P-256
	writeEnrollmentU16(&area, 0x0010) // KDF: null
	writeEnrollmentTPM2B(&area, public.X.FillBytes(make([]byte, 32)))
	writeEnrollmentTPM2B(&area, public.Y.FillBytes(make([]byte, 32)))
	return area.Bytes()
}

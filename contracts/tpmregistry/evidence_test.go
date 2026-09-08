package tpmregistry

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

func TestValidateEvidenceAndMakeCredential(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test TPM manufacturer root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	ekKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ekTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test EK"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment, UnknownExtKeyUsage: []asn1.ObjectIdentifier{ekCertificateOID},
	}
	ekCertificateDER, err := x509.CreateCertificate(rand.Reader, ekTemplate, root, &ekKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	attestationKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	attestationDER, err := x509.MarshalPKIXPublicKey(&attestationKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	workKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vrfKey, err := worldcrypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	profile := []byte(`{"name":"test-rsa-ek-p256-work","version":1}`)
	evidence := &Evidence{
		Version: EvidenceVersion, EKCertificateDER: ekCertificateDER,
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
	validated, err := policy.ValidateEvidence(chainID, registry, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if validated.WorkKeyHash != worldcrypto.Keccak256Hash(evidence.WorkPublicKey) || validated.DID == (common.Hash{}) {
		t.Fatal("validated evidence derived incorrect enrollment values")
	}
	t.Run("equivalent EK exponent has one identity", func(t *testing.T) {
		alternate := *evidence
		alternate.EKPublicArea = append([]byte(nil), evidence.EKPublicArea...)
		// RSA-2048 EK profile: attributes, 32-byte policy, AES-CFB,
		// NULL scheme and keyBits precede the four-byte exponent at 52.
		binary.BigEndian.PutUint32(alternate.EKPublicArea[52:56], 0)
		result, err := policy.ValidateEvidence(chainID, registry, &alternate)
		if err != nil {
			t.Fatal(err)
		}
		if result.DeviceNullifier != validated.DeviceNullifier || result.DID != validated.DID || !bytes.Equal(result.EKName, validated.EKName) {
			t.Fatal("equivalent encodings of one certified EK created different identities")
		}
	})
	t.Run("forged EK auth policy is rejected", func(t *testing.T) {
		alternate := *evidence
		alternate.EKPublicArea = append([]byte(nil), evidence.EKPublicArea...)
		alternate.EKPublicArea[10] ^= 1
		if _, err := policy.ValidateEvidence(chainID, registry, &alternate); err == nil {
			t.Fatal("claimant-controlled EK authPolicy was accepted")
		}
	})
	t.Run("noncanonical EK attributes are rejected", func(t *testing.T) {
		alternate := *evidence
		alternate.EKPublicArea = append([]byte(nil), evidence.EKPublicArea...)
		attributes := binary.BigEndian.Uint32(alternate.EKPublicArea[4:8])
		binary.BigEndian.PutUint32(alternate.EKPublicArea[4:8], attributes|0x400) // noDA
		if _, err := policy.ValidateEvidence(chainID, registry, &alternate); err == nil {
			t.Fatal("an unapproved EK template was accepted")
		}
	})
	t.Run("VRF encoding agrees with consensus", func(t *testing.T) {
		compressed := worldcrypto.CompressPubkey(&vrfKey.PublicKey)
		if validated.VRFKeyHash != worldcrypto.Keccak256Hash(compressed) {
			t.Error("uncompressed enrollment VRF key does not bind consensus compressed key")
		}
		alternate := *evidence
		alternate.VRFPublicKey = compressed
		result, err := policy.ValidateEvidence(chainID, registry, &alternate)
		if err != nil {
			t.Fatal(err)
		}
		if result.VRFKeyHash != validated.VRFKeyHash {
			t.Fatal("VRF key encodings produced different registered key hashes")
		}
	})
	t.Run("different certified EK has different identity", func(t *testing.T) {
		otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		otherCertificate, err := x509.CreateCertificate(rand.Reader, ekTemplate, root, &otherKey.PublicKey, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		alternate := *evidence
		alternate.EKCertificateDER = otherCertificate
		alternate.EKPublicArea = marshalRSAEnrollmentPublic(&otherKey.PublicKey, true)
		result, err := policy.ValidateEvidence(chainID, registry, &alternate)
		if err != nil {
			t.Fatal(err)
		}
		if result.DeviceNullifier == validated.DeviceNullifier || result.DID == validated.DID {
			t.Fatal("different certified EKs were merged into one identity")
		}
	})
	credentialBlob, encryptedSecret, err := MakeCredential(evidence, bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if len(credentialBlob) == 0 || len(encryptedSecret) != 256 {
		t.Fatalf("unexpected credential sizes: %d, %d", len(credentialBlob), len(encryptedSecret))
	}

	mutated := *evidence
	mutated.EKCertificateDER = append([]byte(nil), evidence.EKCertificateDER...)
	mutated.EKCertificateDER[len(mutated.EKCertificateDER)-1] ^= 1
	if _, err := policy.ValidateEvidence(chainID, registry, &mutated); err == nil {
		t.Fatal("tampered EK certificate was accepted")
	}
	if DeviceNullifier(big.NewInt(104), registry, validated.EKName) == validated.DeviceNullifier {
		t.Fatal("device nullifier was not chain-separated")
	}
}

func marshalRSAEnrollmentPublic(public *rsa.PublicKey, endorsement bool) []byte {
	const (
		algRSA    = 0x0001
		algAES    = 0x0006
		algSHA256 = 0x000b
		algNull   = 0x0010
		algRSASSA = 0x0014
		algCFB    = 0x0043
	)
	attributes := uint32(tpmwork.ObjectFixedTPM | tpmwork.ObjectFixedParent | tpmwork.ObjectSensitiveDataOrigin | tpmwork.ObjectRestricted)
	if endorsement {
		attributes |= tpmwork.ObjectDecrypt | 0x80 // adminWithPolicy
	} else {
		attributes |= tpmwork.ObjectSignEncrypt
	}
	var area bytes.Buffer
	writeEnrollmentU16(&area, algRSA)
	writeEnrollmentU16(&area, algSHA256)
	_ = binary.Write(&area, binary.BigEndian, attributes)
	if endorsement {
		// Standard RSA-2048 EK endorsement PolicySecret policy.
		writeEnrollmentTPM2B(&area, common.FromHex("837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa"))
	} else {
		writeEnrollmentTPM2B(&area, nil)
	}
	if endorsement {
		writeEnrollmentU16(&area, algAES)
		writeEnrollmentU16(&area, 128)
		writeEnrollmentU16(&area, algCFB)
		writeEnrollmentU16(&area, algNull)
	} else {
		writeEnrollmentU16(&area, algNull)
		writeEnrollmentU16(&area, algRSASSA)
		writeEnrollmentU16(&area, algSHA256)
	}
	writeEnrollmentU16(&area, 2048)
	_ = binary.Write(&area, binary.BigEndian, uint32(public.E))
	writeEnrollmentTPM2B(&area, public.N.FillBytes(make([]byte, 256)))
	return area.Bytes()
}

func writeEnrollmentU16(output *bytes.Buffer, value int) {
	_ = binary.Write(output, binary.BigEndian, uint16(value))
}

func writeEnrollmentTPM2B(output *bytes.Buffer, value []byte) {
	writeEnrollmentU16(output, len(value))
	output.Write(value)
}

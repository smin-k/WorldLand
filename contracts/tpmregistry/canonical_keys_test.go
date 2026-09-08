package tpmregistry

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/rlp"
)

func TestCanonicalVRFPublicKeyRejectsMalformedKeys(t *testing.T) {
	for _, encoded := range [][]byte{
		nil,
		make([]byte, 32),
		append([]byte{2}, bytes.Repeat([]byte{0xff}, 32)...),
		append([]byte{4}, make([]byte, 64)...),
		append([]byte{6}, make([]byte, 64)...),
	} {
		if _, err := CanonicalVRFPublicKey(encoded); err == nil {
			t.Fatalf("accepted malformed %d-byte VRF key", len(encoded))
		}
		if _, err := VRFKeyHash(encoded); err == nil {
			t.Fatalf("hashed malformed %d-byte VRF key", len(encoded))
		}
	}
}

func TestPolicyDigestSeparatesCanonicalEnrollmentRules(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "policy digest test"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: time.Unix(1, 0), NotAfter: time.Unix(2_000_000_000, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	policy := &Policy{Version: 1, RootCertificates: []*x509.Certificate{root}, RequireEKCertificateOID: true, MaxEvidenceBytes: 1 << 20}
	current, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	// This is the exact pre-fix policy encoding. A validator with the old
	// permissive EK/65-byte VRF rules must not advertise the new policy digest.
	legacy, err := rlp.EncodeToBytes(struct {
		Version                 uint32
		RootHashes              []common.Hash
		RequireEKCertificateOID bool
		MaxEvidenceBytes        uint64
		AllowedProfileHashes    []common.Hash
	}{policy.Version, []common.Hash{crypto.Keccak256Hash(root.Raw)}, policy.RequireEKCertificateOID, policy.MaxEvidenceBytes, nil})
	if err != nil {
		t.Fatal(err)
	}
	if current == crypto.Keccak256Hash(legacy) {
		t.Fatal("new canonicalization rules retained the legacy policy digest")
	}
}

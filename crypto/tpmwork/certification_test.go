package tpmwork

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"testing"
)

func TestVerifyKeyCertification(t *testing.T) {
	certification := makeTestCertification(t)
	if err := VerifyKeyCertification(certification); err != nil {
		t.Fatalf("valid certification rejected: %v", err)
	}
}

func TestVerifyKeyCertificationRejectsTampering(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(*KeyCertification)
	}{
		{
			name: "challenge",
			tamper: func(c *KeyCertification) {
				c.Challenge[0] ^= 1
			},
		},
		{
			name: "work public key",
			tamper: func(c *KeyCertification) {
				c.WorkPublicKey[1] ^= 1
			},
		},
		{
			name: "work public area",
			tamper: func(c *KeyCertification) {
				c.WorkPublicArea[len(c.WorkPublicArea)-1] ^= 1
			},
		},
		{
			name: "statement",
			tamper: func(c *KeyCertification) {
				c.AttestationStatement[len(c.AttestationStatement)-1] ^= 1
			},
		},
		{
			name: "signature",
			tamper: func(c *KeyCertification) {
				c.AttestationSignature[len(c.AttestationSignature)-1] ^= 1
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			certification := cloneCertification(makeTestCertification(t))
			test.tamper(certification)
			if err := VerifyKeyCertification(certification); err == nil {
				t.Fatal("tampered certification accepted")
			}
		})
	}
}

func makeTestCertification(t *testing.T) *KeyCertification {
	t.Helper()
	workKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attestationKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	workArea := marshalTestECCPublicArea(&workKey.PublicKey)
	attestationArea := marshalTestRSAPublicArea(&attestationKey.PublicKey)
	_, workName, err := parseTPMPublicArea(workArea)
	if err != nil {
		t.Fatal(err)
	}
	_, attestationName, err := parseTPMPublicArea(attestationArea)
	if err != nil {
		t.Fatal(err)
	}
	challenge := []byte("worldland-test-challenge")
	statement := marshalTestCertifyStatement(attestationName, challenge, workName)
	digest := sha256.Sum256(statement)
	signature, err := rsa.SignPKCS1v15(rand.Reader, attestationKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	var tpmSignature bytes.Buffer
	writeU16(&tpmSignature, tpmAlgRSASSA)
	writeU16(&tpmSignature, tpmAlgSHA256)
	writeTPM2B(&tpmSignature, signature)
	attestationDER, err := x509.MarshalPKIXPublicKey(&attestationKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &KeyCertification{
		Version:               CertificationVersion,
		Challenge:             challenge,
		WorkPublicKey:         elliptic.Marshal(elliptic.P256(), workKey.X, workKey.Y),
		WorkPublicArea:        workArea,
		AttestationPublicKey:  attestationDER,
		AttestationPublicArea: attestationArea,
		AttestationStatement:  statement,
		AttestationSignature:  tpmSignature.Bytes(),
	}
}

func marshalTestECCPublicArea(public *ecdsa.PublicKey) []byte {
	var area bytes.Buffer
	writeU16(&area, tpmAlgECC)
	writeU16(&area, tpmAlgSHA256)
	writeU32(&area, tpmaObjectFixedTPM|tpmaObjectFixedParent|tpmaObjectSensitiveDataOrigin|tpmaObjectSignEncrypt)
	writeTPM2B(&area, nil)
	writeU16(&area, tpmAlgNull)
	writeU16(&area, tpmAlgECDSA)
	writeU16(&area, tpmAlgSHA256)
	writeU16(&area, tpmECCNISTP256)
	writeU16(&area, tpmAlgNull)
	writeTPM2B(&area, public.X.FillBytes(make([]byte, 32)))
	writeTPM2B(&area, public.Y.FillBytes(make([]byte, 32)))
	return area.Bytes()
}

func marshalTestRSAPublicArea(public *rsa.PublicKey) []byte {
	var area bytes.Buffer
	writeU16(&area, tpmAlgRSA)
	writeU16(&area, tpmAlgSHA256)
	writeU32(&area, tpmaObjectFixedTPM|tpmaObjectFixedParent|tpmaObjectSensitiveDataOrigin|tpmaObjectRestricted|tpmaObjectSignEncrypt)
	writeTPM2B(&area, nil)
	writeU16(&area, tpmAlgNull)
	writeU16(&area, tpmAlgRSASSA)
	writeU16(&area, tpmAlgSHA256)
	writeU16(&area, uint16(public.N.BitLen()))
	writeU32(&area, uint32(public.E))
	writeTPM2B(&area, public.N.Bytes())
	return area.Bytes()
}

func marshalTestCertifyStatement(signerName, challenge, workName []byte) []byte {
	var statement bytes.Buffer
	writeU32(&statement, tpmGeneratedValue)
	writeU16(&statement, tpmSTAttestCertify)
	writeTPM2B(&statement, signerName)
	writeTPM2B(&statement, challenge)
	statement.Write(make([]byte, 17+8))
	writeTPM2B(&statement, workName)
	writeTPM2B(&statement, workName)
	return statement.Bytes()
}

func writeU16(buffer *bytes.Buffer, value uint16) {
	_ = binary.Write(buffer, binary.BigEndian, value)
}

func writeU32(buffer *bytes.Buffer, value uint32) {
	_ = binary.Write(buffer, binary.BigEndian, value)
}

func writeTPM2B(buffer *bytes.Buffer, value []byte) {
	writeU16(buffer, uint16(len(value)))
	buffer.Write(value)
}

func cloneCertification(c *KeyCertification) *KeyCertification {
	return &KeyCertification{
		Version:               c.Version,
		Challenge:             append([]byte(nil), c.Challenge...),
		WorkPublicKey:         append([]byte(nil), c.WorkPublicKey...),
		WorkPublicArea:        append([]byte(nil), c.WorkPublicArea...),
		AttestationPublicKey:  append([]byte(nil), c.AttestationPublicKey...),
		AttestationPublicArea: append([]byte(nil), c.AttestationPublicArea...),
		AttestationStatement:  append([]byte(nil), c.AttestationStatement...),
		AttestationSignature:  append([]byte(nil), c.AttestationSignature...),
	}
}

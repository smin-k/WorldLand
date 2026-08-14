package tpmwork

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestVerifyDigest(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("TPM-gated work"))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, SignatureSize)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	signature, err = NormalizeSignature(signature)
	if err != nil {
		t.Fatal(err)
	}
	public := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	if !VerifyDigest(public, digest[:], signature) {
		t.Fatal("valid P-256 work signature rejected")
	}
	signature[0] ^= 1
	if VerifyDigest(public, digest[:], signature) {
		t.Fatal("modified work signature accepted")
	}
}

func TestVerifyDigestRejectsHighSMalleation(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("one TPM call, one canonical input"))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(key.Params().N), 1)) <= 0 {
		s.Sub(key.Params().N, s)
	}
	highS := make([]byte, SignatureSize)
	r.FillBytes(highS[:32])
	s.FillBytes(highS[32:])
	public := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	if VerifyDigest(public, digest[:], highS) {
		t.Fatal("high-s malleated signature accepted")
	}
	normalized, err := NormalizeSignature(highS)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDigest(public, digest[:], normalized) {
		t.Fatal("normalized low-s signature rejected")
	}
}

func TestVerifyDigestRejectsMalformedValues(t *testing.T) {
	public := make([]byte, PublicKeySize)
	public[0] = 4
	if VerifyDigest(public, make([]byte, DigestSize), make([]byte, SignatureSize)) {
		t.Fatal("invalid public key accepted")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	zero := make([]byte, SignatureSize)
	if VerifyDigest(encoded, make([]byte, DigestSize), zero) {
		t.Fatal("zero signature accepted")
	}
	tooLarge := make([]byte, SignatureSize)
	new(big.Int).Set(elliptic.P256().Params().N).FillBytes(tooLarge[:32])
	tooLarge[63] = 1
	if VerifyDigest(encoded, make([]byte, DigestSize), tooLarge) {
		t.Fatal("out-of-range signature accepted")
	}
}

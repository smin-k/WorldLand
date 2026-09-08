// tpmpreflight exercises a real platform TPM without mining or network consensus.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/cryptoecc/WorldLand/crypto/tpmwork"
	gotpm "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/credactivation"
)

func main() {
	create := flag.Bool("create", false, "create dedicated persistent test work/AK keys if absent")
	flag.Parse()
	result := map[string]interface{}{"mining": false, "certificateChainTrusted": false}
	err := run(*create, result)
	if err != nil {
		result["error"] = err.Error()
	}
	result["success"] = err == nil
	encoded, _ := json.Marshal(result)
	fmt.Printf("WORLDLAND_TPM_PREFLIGHT_JSON=%s\n", encoded)
	if err != nil {
		os.Exit(1)
	}
}

func run(create bool, result map[string]interface{}) error {
	const work = "WorldLand-TPM-Work-Test"
	const ak = "WorldLand-TPM-AIK-Test"
	s, err := tpmwork.OpenPlatformSigner(work, create)
	if err != nil {
		return err
	}
	defer s.Close()
	pub := s.PublicKey()
	result["workPublicKey"] = hex.EncodeToString(pub)
	digest := sha256.Sum256([]byte("WorldLand real TPM preflight; no mining"))
	for i := 0; i < 5; i++ {
		sig, err := s.SignDigest(digest[:])
		if err != nil {
			return err
		}
		if !tpmwork.VerifyDigest(pub, digest[:], sig) {
			return fmt.Errorf("signature verification failed")
		}
	}
	result["signaturesVerified"] = 5
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	c, err := s.CertifyWorkKey(ak, create, nonce)
	if err != nil {
		return err
	}
	if err := tpmwork.VerifyKeyCertification(c); err != nil {
		return err
	}
	result["certifyVerified"] = true
	if err := s.Close(); err != nil {
		return err
	}
	s, err = tpmwork.OpenPlatformSigner(work, false)
	if err != nil {
		return err
	}
	defer s.Close()
	if !bytes.Equal(pub, s.PublicKey()) {
		return fmt.Errorf("work key changed on reopen")
	}
	result["persistentReopenVerified"] = true
	identity, err := s.EnrollmentIdentity(ak, false, 0, 0)
	if err != nil {
		return err
	}
	result["ekCertificateBytes"] = len(identity.EKCertificateDER)
	ek, _, err := tpmwork.ParsePublicArea(identity.EKPublicArea)
	if err != nil {
		return err
	}
	_, name, err := tpmwork.ParsePublicArea(identity.AttestationPublicArea)
	if err != nil {
		return err
	}
	if len(name) != 34 {
		return fmt.Errorf("unexpected AK name")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	blob, encrypted, err := credactivation.Generate(&gotpm.HashValue{Alg: gotpm.AlgSHA256, Value: name[2:]}, ek, 16, secret)
	if err != nil {
		return err
	}
	unwrap := func(b []byte) ([]byte, error) {
		if len(b) < 2 || int(binary.BigEndian.Uint16(b)) != len(b)-2 {
			return nil, fmt.Errorf("invalid TPM2B")
		}
		return b[2:], nil
	}
	blob, err = unwrap(blob)
	if err != nil {
		return err
	}
	encrypted, err = unwrap(encrypted)
	if err != nil {
		return err
	}
	activated, err := s.ActivateCredential(ak, 0, blob, encrypted)
	if err != nil {
		return err
	}
	if !bytes.Equal(activated, secret) {
		return fmt.Errorf("activation secret mismatch")
	}
	result["activateCredentialVerified"] = true
	blob = append([]byte(nil), blob...)
	blob[len(blob)-1] ^= 1
	if _, err := s.ActivateCredential(ak, 0, blob, encrypted); err == nil {
		return fmt.Errorf("tampered credential accepted")
	}
	result["tamperedCredentialRejected"] = true
	result["enrollmentIdentity"] = identity
	return nil
}

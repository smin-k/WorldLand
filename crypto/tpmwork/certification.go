package tpmwork

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

const (
	CertificationVersion         = 1
	DefaultRSAEKHandle           = uint32(0x81010001)
	DefaultRSAEKCertificateIndex = uint32(0x01c00002)

	tpmGeneratedValue  = 0xff544347
	tpmSTAttestCertify = 0x8017
	tpmAlgRSA          = 0x0001
	tpmAlgSHA256       = 0x000b
	tpmAlgNull         = 0x0010
	tpmAlgRSASSA       = 0x0014
	tpmAlgECDSA        = 0x0018
	tpmAlgECC          = 0x0023
	tpmECCNISTP256     = 0x0003

	tpmaObjectFixedTPM            = 0x00000002
	tpmaObjectFixedParent         = 0x00000010
	tpmaObjectSensitiveDataOrigin = 0x00000020
	tpmaObjectRestricted          = 0x00010000
	tpmaObjectDecrypt             = 0x00020000
	tpmaObjectSignEncrypt         = 0x00040000
)

// KeyCertification is the portable part of a TPM2_Certify result. It proves
// that WorkPublicArea was loaded in the same TPM as the attestation key and
// binds the proof to Challenge. Trusting AttestationPublicArea as a genuine,
// unique physical TPM still requires separate EK/AK enrollment.
type KeyCertification struct {
	Version               uint32 `json:"version"`
	Challenge             []byte `json:"challenge"`
	WorkPublicKey         []byte `json:"workPublicKey"`
	WorkPublicArea        []byte `json:"workPublicArea"`
	AttestationPublicKey  []byte `json:"attestationPublicKey"`
	AttestationPublicArea []byte `json:"attestationPublicArea"`
	AttestationStatement  []byte `json:"attestationStatement"`
	AttestationSignature  []byte `json:"attestationSignature"`
}

// KeyCertifier is implemented by TPM backends that can create a nonce-bound
// TPM2_Certify statement for a work key.
type KeyCertifier interface {
	CertifyWorkKey(attestationKeyName string, create bool, challenge []byte) (*KeyCertification, error)
}

// EnrollmentIdentity contains the public TPM identity material required by a
// remote registration validator. All fields are public; no private key or
// authorization value is exported.
type EnrollmentIdentity struct {
	EKCertificateDER      []byte `json:"ekCertificateDER"`
	EKPublicArea          []byte `json:"ekPublicArea"`
	EKName                []byte `json:"ekName"`
	AttestationPublicKey  []byte `json:"attestationPublicKey"`
	AttestationPublicArea []byte `json:"attestationPublicArea"`
	AttestationName       []byte `json:"attestationName"`
}

// CredentialActivator is implemented by TPM backends capable of returning
// the secret from a verifier-created MakeCredential challenge.
type CredentialActivator interface {
	EnrollmentIdentity(attestationKeyName string, create bool, ekHandle, ekCertificateIndex uint32) (*EnrollmentIdentity, error)
	ActivateCredential(attestationKeyName string, ekHandle uint32, credentialBlob, encryptedSecret []byte) ([]byte, error)
}

// ParsePublicArea returns the public key and canonical TPM Name represented by
// a TPMT_PUBLIC byte string.
func ParsePublicArea(area []byte) (interface{}, []byte, error) {
	return parseTPMPublicArea(area)
}

// VerifyPublicAreaAttributes checks the required and forbidden TPMA_OBJECT bits.
func VerifyPublicAreaAttributes(area []byte, required, forbidden uint32) error {
	return verifyTPMObjectAttributes(area, required, forbidden)
}

const (
	ObjectFixedTPM            = tpmaObjectFixedTPM
	ObjectFixedParent         = tpmaObjectFixedParent
	ObjectSensitiveDataOrigin = tpmaObjectSensitiveDataOrigin
	ObjectRestricted          = tpmaObjectRestricted
	ObjectDecrypt             = tpmaObjectDecrypt
	ObjectSignEncrypt         = tpmaObjectSignEncrypt
)

// VerifyKeyCertification checks the TPM statement, challenge, public-area
// names and AIK signature. It intentionally does not claim that the AIK is
// genuine: that requires EK credential activation or an accepted AIK chain.
func VerifyKeyCertification(certification *KeyCertification) error {
	if certification == nil {
		return errors.New("tpmwork: nil key certification")
	}
	if certification.Version != CertificationVersion {
		return fmt.Errorf("tpmwork: unsupported certification version %d", certification.Version)
	}
	if len(certification.Challenge) == 0 {
		return errors.New("tpmwork: empty certification challenge")
	}
	workPublic, workName, err := parseTPMPublicArea(certification.WorkPublicArea)
	if err != nil {
		return fmt.Errorf("tpmwork: parse certified work public area: %w", err)
	}
	workECDSA, ok := workPublic.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("tpmwork: certified work key is not P-256 ECDSA")
	}
	encodedWork := elliptic.Marshal(elliptic.P256(), workECDSA.X, workECDSA.Y)
	if !bytes.Equal(encodedWork, certification.WorkPublicKey) {
		return errors.New("tpmwork: certified TPM public area does not match work public key")
	}
	workRequired := uint32(tpmaObjectFixedTPM | tpmaObjectFixedParent | tpmaObjectSensitiveDataOrigin | tpmaObjectSignEncrypt)
	if err := verifyTPMObjectAttributes(certification.WorkPublicArea, workRequired, tpmaObjectRestricted|tpmaObjectDecrypt); err != nil {
		return fmt.Errorf("tpmwork: invalid work-key attributes: %w", err)
	}

	attestationPublic, _, err := parseTPMPublicArea(certification.AttestationPublicArea)
	if err != nil {
		return fmt.Errorf("tpmwork: parse attestation public area: %w", err)
	}
	attestationRSA, ok := attestationPublic.(*rsa.PublicKey)
	if !ok {
		return errors.New("tpmwork: attestation key is not RSA")
	}
	attestationRequired := uint32(tpmaObjectFixedTPM | tpmaObjectFixedParent | tpmaObjectSensitiveDataOrigin | tpmaObjectRestricted | tpmaObjectSignEncrypt)
	if err := verifyTPMObjectAttributes(certification.AttestationPublicArea, attestationRequired, tpmaObjectDecrypt); err != nil {
		return fmt.Errorf("tpmwork: invalid attestation-key attributes: %w", err)
	}
	parsedDER, err := x509.ParsePKIXPublicKey(certification.AttestationPublicKey)
	if err != nil {
		return fmt.Errorf("tpmwork: parse attestation public key: %w", err)
	}
	derRSA, ok := parsedDER.(*rsa.PublicKey)
	if !ok || derRSA.E != attestationRSA.E || derRSA.N.Cmp(attestationRSA.N) != 0 {
		return errors.New("tpmwork: attestation public area does not match exported public key")
	}

	certifiedName, extraData, err := parseCertifyStatement(certification.AttestationStatement)
	if err != nil {
		return err
	}
	if !bytes.Equal(extraData, certification.Challenge) {
		return errors.New("tpmwork: attestation challenge mismatch")
	}
	if !bytes.Equal(certifiedName, workName) {
		return errors.New("tpmwork: attested object name does not match work public area")
	}
	signature, hashAlgorithm, err := parseRSATPMTSignature(certification.AttestationSignature)
	if err != nil {
		return err
	}
	if hashAlgorithm != tpmAlgSHA256 {
		return fmt.Errorf("tpmwork: unsupported attestation hash algorithm 0x%04x", hashAlgorithm)
	}
	digest := sha256.Sum256(certification.AttestationStatement)
	if err := rsa.VerifyPKCS1v15(attestationRSA, crypto.SHA256, digest[:], signature); err != nil {
		return fmt.Errorf("tpmwork: invalid TPM certification signature: %w", err)
	}
	return nil
}

func verifyTPMObjectAttributes(publicArea []byte, required, forbidden uint32) error {
	if len(publicArea) < 8 {
		return errors.New("short TPMT_PUBLIC attributes")
	}
	attributes := binary.BigEndian.Uint32(publicArea[4:8])
	if attributes&required != required {
		return fmt.Errorf("missing required flags: got 0x%08x, require 0x%08x", attributes, required)
	}
	if attributes&forbidden != 0 {
		return fmt.Errorf("forbidden flags present: got 0x%08x, forbid 0x%08x", attributes, forbidden)
	}
	return nil
}

func parseTPMPublicArea(area []byte) (interface{}, []byte, error) {
	r := newTPMReader(area)
	keyType, ok := r.u16()
	if !ok {
		return nil, nil, errors.New("short TPMT_PUBLIC")
	}
	nameAlgorithm, ok := r.u16()
	if !ok || nameAlgorithm != tpmAlgSHA256 {
		return nil, nil, fmt.Errorf("unsupported TPM name algorithm 0x%04x", nameAlgorithm)
	}
	if _, ok = r.u32(); !ok { // objectAttributes
		return nil, nil, errors.New("short TPM object attributes")
	}
	if _, ok = r.tpm2b(); !ok { // authPolicy
		return nil, nil, errors.New("short TPM auth policy")
	}
	var public interface{}
	switch keyType {
	case tpmAlgECC:
		if err := skipTPMSymmetricDefinition(r); err != nil {
			return nil, nil, err
		}
		if err := skipTPMScheme(r); err != nil {
			return nil, nil, err
		}
		curve, ok := r.u16()
		if !ok || curve != tpmECCNISTP256 {
			return nil, nil, fmt.Errorf("unsupported TPM ECC curve 0x%04x", curve)
		}
		if err := skipTPMScheme(r); err != nil { // KDF scheme
			return nil, nil, err
		}
		xBytes, ok := r.tpm2b()
		if !ok {
			return nil, nil, errors.New("short TPM ECC x coordinate")
		}
		yBytes, ok := r.tpm2b()
		if !ok {
			return nil, nil, errors.New("short TPM ECC y coordinate")
		}
		x, y := new(big.Int).SetBytes(xBytes), new(big.Int).SetBytes(yBytes)
		if !elliptic.P256().IsOnCurve(x, y) {
			return nil, nil, errors.New("TPM ECC public point is not on P-256")
		}
		public = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	case tpmAlgRSA:
		if err := skipTPMSymmetricDefinition(r); err != nil {
			return nil, nil, err
		}
		if err := skipTPMScheme(r); err != nil {
			return nil, nil, err
		}
		bits, ok := r.u16()
		if !ok {
			return nil, nil, errors.New("short TPM RSA key size")
		}
		exponent, ok := r.u32()
		if !ok {
			return nil, nil, errors.New("short TPM RSA exponent")
		}
		if exponent == 0 {
			exponent = 65537
		}
		modulus, ok := r.tpm2b()
		if !ok || len(modulus)*8 != int(bits) {
			return nil, nil, errors.New("invalid TPM RSA modulus")
		}
		public = &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(exponent)}
	default:
		return nil, nil, fmt.Errorf("unsupported TPM public type 0x%04x", keyType)
	}
	if !r.empty() {
		return nil, nil, errors.New("trailing bytes in TPMT_PUBLIC")
	}
	digest := sha256.Sum256(area)
	name := make([]byte, 2+len(digest))
	binary.BigEndian.PutUint16(name, tpmAlgSHA256)
	copy(name[2:], digest[:])
	return public, name, nil
}

func skipTPMSymmetricDefinition(r *tpmReader) error {
	algorithm, ok := r.u16()
	if !ok {
		return errors.New("short TPM symmetric definition")
	}
	if algorithm != tpmAlgNull {
		if _, ok = r.u16(); !ok { // keyBits
			return errors.New("short TPM symmetric key size")
		}
		if _, ok = r.u16(); !ok { // mode
			return errors.New("short TPM symmetric mode")
		}
	}
	return nil
}

func skipTPMScheme(r *tpmReader) error {
	scheme, ok := r.u16()
	if !ok {
		return errors.New("short TPM scheme")
	}
	if scheme != tpmAlgNull {
		if _, ok = r.u16(); !ok { // scheme hash
			return errors.New("short TPM scheme hash")
		}
	}
	return nil
}

func parseCertifyStatement(statement []byte) (certifiedName, extraData []byte, err error) {
	r := newTPMReader(statement)
	magic, ok := r.u32()
	if !ok || magic != tpmGeneratedValue {
		return nil, nil, errors.New("tpmwork: invalid TPM attestation magic")
	}
	typeTag, ok := r.u16()
	if !ok || typeTag != tpmSTAttestCertify {
		return nil, nil, errors.New("tpmwork: statement is not a TPM certify attestation")
	}
	if _, ok = r.tpm2b(); !ok { // qualifiedSigner
		return nil, nil, errors.New("tpmwork: short qualified signer")
	}
	extraData, ok = r.tpm2b()
	if !ok || !r.skip(17+8) { // clockInfo and firmwareVersion
		return nil, nil, errors.New("tpmwork: short attestation metadata")
	}
	certifiedName, ok = r.tpm2b()
	if !ok {
		return nil, nil, errors.New("tpmwork: short certified name")
	}
	if _, ok = r.tpm2b(); !ok || !r.empty() { // qualifiedName
		return nil, nil, errors.New("tpmwork: malformed certified qualified name")
	}
	return append([]byte(nil), certifiedName...), append([]byte(nil), extraData...), nil
}

func parseRSATPMTSignature(encoded []byte) ([]byte, uint16, error) {
	r := newTPMReader(encoded)
	algorithm, ok := r.u16()
	if !ok || algorithm != tpmAlgRSASSA {
		return nil, 0, fmt.Errorf("tpmwork: unsupported TPM signature algorithm 0x%04x", algorithm)
	}
	hashAlgorithm, ok := r.u16()
	if !ok {
		return nil, 0, errors.New("tpmwork: short TPM signature hash")
	}
	signature, ok := r.tpm2b()
	if !ok || !r.empty() {
		return nil, 0, errors.New("tpmwork: malformed TPM RSA signature")
	}
	return append([]byte(nil), signature...), hashAlgorithm, nil
}

type tpmReader struct{ data []byte }

func newTPMReader(data []byte) *tpmReader { return &tpmReader{data: data} }
func (r *tpmReader) empty() bool          { return len(r.data) == 0 }
func (r *tpmReader) skip(size int) bool {
	if size < 0 || len(r.data) < size {
		return false
	}
	r.data = r.data[size:]
	return true
}
func (r *tpmReader) u16() (uint16, bool) {
	if len(r.data) < 2 {
		return 0, false
	}
	value := binary.BigEndian.Uint16(r.data)
	r.data = r.data[2:]
	return value, true
}
func (r *tpmReader) u32() (uint32, bool) {
	if len(r.data) < 4 {
		return 0, false
	}
	value := binary.BigEndian.Uint32(r.data)
	r.data = r.data[4:]
	return value, true
}
func (r *tpmReader) tpm2b() ([]byte, bool) {
	size, ok := r.u16()
	if !ok || len(r.data) < int(size) {
		return nil, false
	}
	value := r.data[:size]
	r.data = r.data[size:]
	return value, true
}

package tpmwork

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	gotpm "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// deviceSigner is platform-independent for wire-level regression tests. Only
// signer_linux.go opens a real device; there is no software-signing fallback.
type deviceSigner struct {
	mu              sync.Mutex
	rw              io.ReadWriteCloser
	work            tpmutil.Handle
	public          []byte
	certificatePath string
}

var _ Signer = (*deviceSigner)(nil)
var _ KeyCertifier = (*deviceSigner)(nil)
var _ CredentialActivator = (*deviceSigner)(nil)

func linuxKeyHandle(name string, attestation bool) (tpmutil.Handle, error) {
	aliases := map[string]uint32{"WorldLand-TPM-Work": 0x81010020, "WorldLand-TPM-Work-Test": 0x81010022}
	if attestation {
		aliases = map[string]uint32{"WorldLand-TPM-AIK": 0x81010021, "WorldLand-TPM-AIK-Test": 0x81010023}
	}
	if h, ok := aliases[name]; ok {
		return tpmutil.Handle(h), nil
	}
	if !strings.HasPrefix(name, "0x") {
		return 0, errors.New("tpmwork: Linux key name must be a documented WorldLand alias or explicit 0x81xxxxxx persistent handle")
	}
	h, err := strconv.ParseUint(name[2:], 16, 32)
	// Owner persistent range only. Reserve the standard EK and SRK handles.
	if err != nil || h < 0x81000002 || h >= 0x81800000 || h == uint64(DefaultRSAEKHandle) {
		return 0, errors.New("tpmwork: invalid or reserved Linux persistent key handle")
	}
	return tpmutil.Handle(h), nil
}

func deviceWorkTemplate() gotpm.Public {
	return gotpm.Public{Type: gotpm.AlgECC, NameAlg: gotpm.AlgSHA256,
		Attributes:    gotpm.FlagSignerDefault &^ gotpm.FlagRestricted,
		ECCParameters: &gotpm.ECCParams{CurveID: gotpm.CurveNISTP256, Sign: &gotpm.SigScheme{Alg: gotpm.AlgECDSA, Hash: gotpm.AlgSHA256}}}
}

func deviceAKTemplate() gotpm.Public {
	return gotpm.Public{Type: gotpm.AlgRSA, NameAlg: gotpm.AlgSHA256, Attributes: gotpm.FlagSignerDefault,
		RSAParameters: &gotpm.RSAParams{KeyBits: 2048, Sign: &gotpm.SigScheme{Alg: gotpm.AlgRSASSA, Hash: gotpm.AlgSHA256}}}
}

func deviceStorageTemplate() gotpm.Public {
	return gotpm.Public{Type: gotpm.AlgRSA, NameAlg: gotpm.AlgSHA256, Attributes: gotpm.FlagStorageDefault,
		RSAParameters: &gotpm.RSAParams{KeyBits: 2048, Symmetric: &gotpm.SymScheme{Alg: gotpm.AlgAES, KeyBits: 128, Mode: gotpm.AlgCFB}}}
}

func deviceEKTemplate() gotpm.Public {
	p := deviceStorageTemplate()
	// TCG RSA EK creation uses a 256-byte zero unique field, not an empty one.
	// CreatePrimary incorporates this input into derivation; omitting it creates
	// a different RSA key and cannot match the provisioned EK certificate.
	p.RSAParameters.ModulusRaw = make([]byte, 256)
	p.Attributes = gotpm.FlagFixedTPM | gotpm.FlagFixedParent | gotpm.FlagSensitiveDataOrigin | gotpm.FlagAdminWithPolicy | gotpm.FlagRestricted | gotpm.FlagDecrypt
	p.AuthPolicy, _ = hex.DecodeString("837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa")
	return p
}

func missingDeviceHandle(err error) bool {
	var h gotpm.HandleError
	return errors.As(err, &h) && h.Code == gotpm.RCHandle && h.Handle == 1
}

// TPMs may encode the default RSA exponent either as zero or explicitly.
func deviceMatchesTemplate(p, template gotpm.Public) bool {
	if p.Type == gotpm.AlgRSA && p.RSAParameters != nil && p.RSAParameters.ExponentRaw == 65537 {
		copyParams := *p.RSAParameters
		copyParams.ExponentRaw = 0
		p.RSAParameters = &copyParams
	}
	return p.MatchesTemplate(template)
}

// ensureDeviceKey creates a random child key under a transient storage primary.
// EvictControl is called only with a transient source, so a concurrently occupied
// destination fails instead of deleting it. Wrapped private blobs never hit disk.
func ensureDeviceKey(rw io.ReadWriter, h tpmutil.Handle, create bool, template gotpm.Public) (gotpm.Public, error) {
	p, _, _, err := gotpm.ReadPublic(rw, h)
	if err == nil {
		if !deviceMatchesTemplate(p, template) {
			return gotpm.Public{}, fmt.Errorf("tpmwork: occupied handle 0x%08x has an incompatible key; refusing replacement", h)
		}
		return p, nil
	}
	if !create || !missingDeviceHandle(err) {
		return gotpm.Public{}, fmt.Errorf("tpmwork: read persistent key 0x%08x: %w", h, err)
	}
	parent, _, err := gotpm.CreatePrimary(rw, gotpm.HandleOwner, gotpm.PCRSelection{}, "", "", deviceStorageTemplate())
	if err != nil {
		return gotpm.Public{}, fmt.Errorf("tpmwork: create storage primary (empty owner auth required): %w", err)
	}
	defer gotpm.FlushContext(rw, parent)
	private, public, _, _, _, err := gotpm.CreateKey(rw, parent, gotpm.PCRSelection{}, "", "", template)
	if err != nil {
		return gotpm.Public{}, fmt.Errorf("tpmwork: create TPM child: %w", err)
	}
	child, _, err := gotpm.Load(rw, parent, "", public, private)
	if err != nil {
		return gotpm.Public{}, fmt.Errorf("tpmwork: load TPM child: %w", err)
	}
	defer gotpm.FlushContext(rw, child)
	if err := gotpm.EvictControl(rw, "", gotpm.HandleOwner, child, h); err != nil {
		return gotpm.Public{}, fmt.Errorf("tpmwork: persist key without replacement: %w", err)
	}
	return ensureDeviceKey(rw, h, false, template)
}

func openDeviceSigner(rw io.ReadWriteCloser, h tpmutil.Handle, create bool, certificatePath string) (*deviceSigner, error) {
	p, err := ensureDeviceKey(rw, h, create, deviceWorkTemplate())
	if err != nil {
		return nil, err
	}
	area, err := p.Encode()
	if err != nil {
		return nil, err
	}
	pub, _, err := ParsePublicArea(area)
	if err != nil {
		return nil, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("tpmwork: work key is not P-256")
	}
	return &deviceSigner{rw: rw, work: h, public: elliptic.Marshal(elliptic.P256(), ec.X, ec.Y), certificatePath: certificatePath}, nil
}

func (s *deviceSigner) PublicKey() []byte { return append([]byte(nil), s.public...) }
func (s *deviceSigner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rw == nil {
		return nil
	}
	err := s.rw.Close()
	s.rw = nil
	return err
}

func (s *deviceSigner) SignDigest(digest []byte) ([]byte, error) {
	if len(digest) != DigestSize {
		return nil, errors.New("tpmwork: digest must be 32 bytes")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rw == nil {
		return nil, errors.New("tpmwork: signer is closed")
	}
	sig, err := gotpm.Sign(s.rw, s.work, "", digest, nil, &gotpm.SigScheme{Alg: gotpm.AlgECDSA, Hash: gotpm.AlgSHA256})
	if err != nil {
		return nil, fmt.Errorf("tpmwork: TPM sign: %w", err)
	}
	if sig == nil || sig.Alg != gotpm.AlgECDSA || sig.ECC == nil || sig.ECC.HashAlg != gotpm.AlgSHA256 || sig.ECC.R == nil || sig.ECC.S == nil || sig.ECC.R.Sign() <= 0 || sig.ECC.S.Sign() <= 0 || sig.ECC.R.BitLen() > 256 || sig.ECC.S.BitLen() > 256 {
		return nil, errors.New("tpmwork: invalid TPM ECDSA signature")
	}
	raw := make([]byte, SignatureSize)
	sig.ECC.R.FillBytes(raw[:32])
	sig.ECC.S.FillBytes(raw[32:])
	raw, err = NormalizeSignature(raw)
	if err != nil {
		return nil, err
	}
	if !VerifyDigest(s.public, digest, raw) {
		return nil, errors.New("tpmwork: signature does not match opened work key")
	}
	return raw, nil
}

func (s *deviceSigner) attestationKey(name string, create bool) (tpmutil.Handle, gotpm.Public, error) {
	h, err := linuxKeyHandle(name, true)
	if err != nil {
		return 0, gotpm.Public{}, err
	}
	if h == s.work {
		return 0, gotpm.Public{}, errors.New("tpmwork: AK and work handles must differ")
	}
	p, err := ensureDeviceKey(s.rw, h, create, deviceAKTemplate())
	return h, p, err
}

func (s *deviceSigner) CertifyWorkKey(name string, create bool, challenge []byte) (*KeyCertification, error) {
	if len(challenge) == 0 || len(challenge) > 64 {
		return nil, errors.New("tpmwork: certification challenge must contain 1..64 bytes")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rw == nil {
		return nil, errors.New("tpmwork: signer is closed")
	}
	ak, ap, err := s.attestationKey(name, create)
	if err != nil {
		return nil, err
	}
	wp, _, _, err := gotpm.ReadPublic(s.rw, s.work)
	if err != nil {
		return nil, err
	}
	wa, err := wp.Encode()
	if err != nil {
		return nil, err
	}
	aa, err := ap.Encode()
	if err != nil {
		return nil, err
	}
	pub, _, err := ParsePublicArea(aa)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	statement, signature, err := gotpm.CertifyEx(s.rw, "", "", s.work, ak, challenge, gotpm.SigScheme{Alg: gotpm.AlgRSASSA, Hash: gotpm.AlgSHA256})
	if err != nil {
		return nil, fmt.Errorf("tpmwork: TPM certify: %w", err)
	}
	c := &KeyCertification{Version: CertificationVersion, Challenge: append([]byte(nil), challenge...), WorkPublicKey: s.PublicKey(), WorkPublicArea: wa, AttestationPublicKey: der, AttestationPublicArea: aa, AttestationStatement: statement, AttestationSignature: signature}
	if err := VerifyKeyCertification(c); err != nil {
		return nil, err
	}
	return c, nil
}

// A missing standard EK is derived transiently from the endorsement hierarchy.
// No EK is persisted, evicted or replaced. Non-default handles are read-only.
func (s *deviceSigner) endorsementKey(handle uint32) (tpmutil.Handle, func(), error) {
	if handle == 0 {
		handle = DefaultRSAEKHandle
	}
	h := tpmutil.Handle(handle)
	p, _, _, err := gotpm.ReadPublic(s.rw, h)
	cleanup := func() {}
	if err != nil {
		if handle != DefaultRSAEKHandle || !missingDeviceHandle(err) {
			return 0, cleanup, fmt.Errorf("tpmwork: read EK: %w", err)
		}
		h, _, err = gotpm.CreatePrimary(s.rw, gotpm.HandleEndorsement, gotpm.PCRSelection{}, "", "", deviceEKTemplate())
		if err != nil {
			return 0, cleanup, fmt.Errorf("tpmwork: derive standard EK: %w", err)
		}
		cleanup = func() { gotpm.FlushContext(s.rw, h) }
		p, _, _, err = gotpm.ReadPublic(s.rw, h)
	}
	if err != nil {
		cleanup()
		return 0, func() {}, err
	}
	if !deviceMatchesTemplate(p, deviceEKTemplate()) {
		cleanup()
		return 0, func() {}, errors.New("tpmwork: EK does not match standard RSA-2048 template")
	}
	return h, cleanup, nil
}

func matchingEKCertificate(data, area []byte) ([]byte, error) {
	if len(data) == 0 || len(data) > 65536 {
		return nil, errors.New("tpmwork: invalid EK certificate size")
	}
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN")) {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("tpmwork: expected one PEM EK certificate")
		}
		data = block.Bytes
	}
	c, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("tpmwork: parse EK certificate: %w", err)
	}
	pub, _, err := ParsePublicArea(area)
	if err != nil {
		return nil, err
	}
	actual, ok := pub.(*rsa.PublicKey)
	certified, certOK := c.PublicKey.(*rsa.PublicKey)
	if !ok || !certOK || actual.E != certified.E || actual.N.Cmp(certified.N) != 0 {
		return nil, errors.New("tpmwork: certificate does not match TPM EK")
	}
	// Chain, validity and usage policy remain mandatory at the registration verifier.
	return append([]byte(nil), c.Raw...), nil
}

func (s *deviceSigner) EnrollmentIdentity(name string, create bool, ekHandle, index uint32) (*EnrollmentIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rw == nil {
		return nil, errors.New("tpmwork: signer is closed")
	}
	_, ap, err := s.attestationKey(name, create)
	if err != nil {
		return nil, err
	}
	h, cleanup, err := s.endorsementKey(ekHandle)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	ep, _, _, err := gotpm.ReadPublic(s.rw, h)
	if err != nil {
		return nil, err
	}
	ea, err := ep.Encode()
	if err != nil {
		return nil, err
	}
	_, en, err := ParsePublicArea(ea)
	if err != nil {
		return nil, err
	}
	aa, err := ap.Encode()
	if err != nil {
		return nil, err
	}
	pub, an, err := ParsePublicArea(aa)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	var certificate []byte
	if s.certificatePath != "" {
		f, e := os.Open(s.certificatePath)
		if e != nil {
			return nil, e
		}
		certificate, err = io.ReadAll(io.LimitReader(f, 65537))
		f.Close()
	} else {
		if index == 0 {
			index = DefaultRSAEKCertificateIndex
		}
		certificate, err = gotpm.NVReadEx(s.rw, tpmutil.Handle(index), tpmutil.Handle(index), "", 0)
	}
	if err != nil {
		return nil, fmt.Errorf("tpmwork: read EK certificate (or configure WORLDLAND_TPM_EK_CERT): %w", err)
	}
	certificate, err = matchingEKCertificate(certificate, ea)
	if err != nil {
		return nil, err
	}
	return &EnrollmentIdentity{EKCertificateDER: certificate, EKPublicArea: ea, EKName: en, AttestationPublicKey: der, AttestationPublicArea: aa, AttestationName: an}, nil
}

func (s *deviceSigner) ActivateCredential(name string, ekHandle uint32, blob, secret []byte) ([]byte, error) {
	if len(blob) == 0 || len(blob) > 65535 || len(secret) == 0 || len(secret) > 65535 {
		return nil, errors.New("tpmwork: invalid activation challenge size")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rw == nil {
		return nil, errors.New("tpmwork: signer is closed")
	}
	ak, _, err := s.attestationKey(name, false)
	if err != nil {
		return nil, err
	}
	ek, cleanup, err := s.endorsementKey(ekHandle)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	session, _, err := gotpm.StartAuthSession(s.rw, gotpm.HandleNull, gotpm.HandleNull, nonce, nil, gotpm.SessionPolicy, gotpm.AlgNull, gotpm.AlgSHA256)
	if err != nil {
		return nil, err
	}
	defer gotpm.FlushContext(s.rw, session)
	_, _, err = gotpm.PolicySecret(s.rw, gotpm.HandleEndorsement, gotpm.AuthCommand{Session: gotpm.HandlePasswordSession, Attributes: gotpm.AttrContinueSession}, session, nil, nil, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("tpmwork: EK endorsement policy: %w", err)
	}
	result, err := gotpm.ActivateCredentialUsingAuth(s.rw, []gotpm.AuthCommand{{Session: gotpm.HandlePasswordSession, Attributes: gotpm.AttrContinueSession}, {Session: session, Attributes: gotpm.AttrContinueSession}}, ak, ek, blob, secret)
	if err != nil {
		return nil, fmt.Errorf("tpmwork: activate credential: %w", err)
	}
	return result, nil
}

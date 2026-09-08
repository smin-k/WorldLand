package tpmwork

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	gotpm "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// Scripted wire responses exercise the production backend without touching the
// host TPM. These unit fixtures are not hardware or cloud validation results.
type deviceWire struct {
	t         *testing.T
	codes     []uint32
	responses [][]byte
	pending   *bytes.Reader
	closed    int
	commands  [][]byte
}

func (w *deviceWire) Write(p []byte) (int, error) {
	w.commands = append(w.commands, append([]byte(nil), p...))
	if len(p) < 10 || len(w.codes) == 0 {
		w.t.Fatal("unexpected TPM command")
	}
	if got := binary.BigEndian.Uint32(p[6:10]); got != w.codes[0] {
		w.t.Fatalf("command %x, want %x", got, w.codes[0])
	}
	w.codes = w.codes[1:]
	w.pending = bytes.NewReader(w.responses[0])
	w.responses = w.responses[1:]
	return len(p), nil
}

func TestDeviceCreatePersistsOnlyTransientChildAndFlushes(t *testing.T) {
	_, work := deviceTestWork(t)
	parentKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	parent := deviceStorageTemplate()
	parent.RSAParameters.ModulusRaw = parentKey.N.FillBytes(make([]byte, 256))
	parentArea, _ := parent.Encode()
	workArea, _ := work.Encode()
	_, workName, _ := ParsePublicArea(workArea)
	creation, err := (&gotpm.CreationData{ParentNameAlg: gotpm.AlgNull}).EncodeCreationData()
	if err != nil {
		t.Fatal(err)
	}
	ticket := gotpm.Ticket{Type: 0x8021, Hierarchy: gotpm.HandleOwner}
	primaryParams, _ := tpmutil.Pack(tpmutil.U16Bytes(parentArea), tpmutil.U16Bytes(creation), tpmutil.U16Bytes(nil), ticket, tpmutil.U16Bytes(nil))
	primaryBody, _ := tpmutil.Pack(tpmutil.Handle(0x80000000), uint32(len(primaryParams)), tpmutil.RawBytes(primaryParams))
	createBody, _ := tpmutil.Pack(tpmutil.U16Bytes{1}, tpmutil.U16Bytes(workArea), tpmutil.U16Bytes(creation), tpmutil.U16Bytes(nil), ticket)
	loadBody, _ := tpmutil.Pack(tpmutil.Handle(0x80000001), uint32(2+len(workName)), tpmutil.U16Bytes(workName))
	for _, collision := range []bool{false, true} {
		w := &deviceWire{t: t, codes: []uint32{0x173, 0x131, 0x153, 0x157, 0x120}, responses: [][]byte{deviceResponse(0x18b, false, nil), deviceResponse(0, false, primaryBody), deviceResponse(0, true, createBody), deviceResponse(0, false, loadBody)}}
		if collision {
			w.responses = append(w.responses, deviceResponse(0x14c, false, nil))
		} else {
			w.responses = append(w.responses, deviceResponse(0, true, nil), devicePublicResponse(t, work))
			w.codes = append(w.codes, 0x173)
		}
		w.codes = append(w.codes, 0x165, 0x165)
		w.responses = append(w.responses, deviceResponse(0, false, nil), deviceResponse(0, false, nil))
		_, err := openDeviceSigner(w, 0x81010020, true, "")
		if collision {
			if err == nil {
				t.Fatal("ignored occupied destination")
			}
		} else if err != nil {
			t.Fatal(err)
		}
		if len(w.codes) != 0 {
			t.Fatal("transient handles not flushed")
		}
		evict := w.commands[4]
		if binary.BigEndian.Uint32(evict[14:18]) != 0x80000001 || binary.BigEndian.Uint32(evict[len(evict)-4:]) != 0x81010020 {
			t.Fatal("EvictControl must persist transient child, never evict an existing object")
		}
	}
}
func (w *deviceWire) Read(p []byte) (int, error) {
	if w.pending == nil {
		return 0, io.EOF
	}
	return w.pending.Read(p)
}
func (w *deviceWire) Close() error { w.closed++; return nil }
func deviceResponse(code uint32, sessions bool, body []byte) []byte {
	tag := uint16(0x8001)
	if sessions {
		tag = 0x8002
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(len(body)))
		body = append(b, body...)
	}
	out := make([]byte, 10)
	binary.BigEndian.PutUint16(out, tag)
	binary.BigEndian.PutUint32(out[2:], uint32(10+len(body)))
	binary.BigEndian.PutUint32(out[6:], code)
	return append(out, body...)
}
func devicePublicResponse(t *testing.T, p gotpm.Public) []byte {
	t.Helper()
	area, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	_, name, err := ParsePublicArea(area)
	if err != nil {
		t.Fatal(err)
	}
	body, err := tpmutil.Pack(tpmutil.U16Bytes(area), tpmutil.U16Bytes(name), tpmutil.U16Bytes(name))
	if err != nil {
		t.Fatal(err)
	}
	return deviceResponse(0, false, body)
}
func deviceTestWork(t *testing.T) (*ecdsa.PrivateKey, gotpm.Public) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := deviceWorkTemplate()
	p.ECCParameters.Point = gotpm.ECPoint{XRaw: k.X.FillBytes(make([]byte, 32)), YRaw: k.Y.FillBytes(make([]byte, 32))}
	return k, p
}

func TestLinuxKeyHandles(t *testing.T) {
	if unique := deviceEKTemplate().RSAParameters.ModulusRaw; len(unique) != 256 || !bytes.Equal(unique, make([]byte, 256)) {
		t.Fatal("RSA EK creation must use the TCG 256-byte zero unique field")
	}
	for _, tc := range []struct {
		name string
		ak   bool
		want uint32
	}{{"WorldLand-TPM-Work", false, 0x81010020}, {"WorldLand-TPM-AIK", true, 0x81010021}, {"WorldLand-TPM-Work-Test", false, 0x81010022}, {"WorldLand-TPM-AIK-Test", true, 0x81010023}, {"0x81011000", false, 0x81011000}} {
		h, err := linuxKeyHandle(tc.name, tc.ak)
		if err != nil || uint32(h) != tc.want {
			t.Fatalf("%s: %x %v", tc.name, h, err)
		}
	}
	for _, name := range []string{"", "arbitrary-name", "WorldLand-TPM-AIK", "0x81010001", "0x81000001", "0x80000000", "0x81800000", "0x100000000"} {
		if _, err := linuxKeyHandle(name, false); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
}

func TestDeviceNeverCreatesOnUnknownErrorOrWithoutOptIn(t *testing.T) {
	for _, tc := range []struct {
		code   uint32
		create bool
	}{{0x18b, false}, {0x101, true}, {0x18e, true}} {
		w := &deviceWire{t: t, codes: []uint32{0x173}, responses: [][]byte{deviceResponse(tc.code, false, nil)}}
		if _, err := openDeviceSigner(w, 0x81010020, tc.create, ""); err == nil {
			t.Fatal("expected read failure")
		}
		if len(w.codes) != 0 {
			t.Fatal("expected ReadPublic")
		}
	}
	if !missingDeviceHandle(gotpm.HandleError{Code: gotpm.RCHandle, Handle: 1}) || missingDeviceHandle(errors.New("missing")) {
		t.Fatal("incorrect missing-handle detection")
	}
}

func TestDeviceRejectsOccupiedIncompatibleKey(t *testing.T) {
	_, p := deviceTestWork(t)
	p.Attributes &^= gotpm.FlagFixedTPM
	w := &deviceWire{t: t, codes: []uint32{0x173}, responses: [][]byte{devicePublicResponse(t, p)}}
	if _, err := openDeviceSigner(w, 0x81010020, true, ""); err == nil {
		t.Fatal("accepted incompatible occupied key")
	}
}

func TestDeviceSignAndClose(t *testing.T) {
	k, p := deviceTestWork(t)
	digest := sha256.Sum256([]byte("linux-wire-test"))
	r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately feed high-s to exercise normalization.
	half := new(big.Int).Rsh(new(big.Int).Set(k.Params().N), 1)
	if s.Cmp(half) <= 0 {
		s.Sub(k.Params().N, s)
	}
	sig := gotpm.Signature{Alg: gotpm.AlgECDSA, ECC: &gotpm.SignatureECC{HashAlg: gotpm.AlgSHA256, R: r, S: s}}
	encoded, err := sig.Encode()
	if err != nil {
		t.Fatal(err)
	}
	w := &deviceWire{t: t, codes: []uint32{0x173, 0x15d}, responses: [][]byte{devicePublicResponse(t, p), deviceResponse(0, true, encoded)}}
	signer, err := openDeviceSigner(w, 0x81010020, false, "")
	if err != nil {
		t.Fatal(err)
	}
	copied := signer.PublicKey()
	copied[0] = 0
	if _, err := signer.SignDigest([]byte{1}); err == nil {
		t.Fatal("accepted short digest")
	}
	raw, err := signer.SignDigest(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyDigest(signer.PublicKey(), digest[:], raw) {
		t.Fatal("invalid signature")
	}
	signer.Close()
	signer.Close()
	if w.closed != 1 {
		t.Fatal("close not idempotent")
	}
	if _, err := signer.SignDigest(digest[:]); err == nil {
		t.Fatal("signed after close")
	}
	if _, err := signer.CertifyWorkKey("WorldLand-TPM-AIK", false, digest[:]); err == nil {
		t.Fatal("certified after close")
	}
	if _, err := signer.EnrollmentIdentity("WorldLand-TPM-AIK", false, 0, 0); err == nil {
		t.Fatal("enrolled after close")
	}
	if _, err := signer.ActivateCredential("WorldLand-TPM-AIK", 0, []byte{1}, []byte{2}); err == nil {
		t.Fatal("activated after close")
	}
}

func TestDeviceCertifyMatchesExistingVerifier(t *testing.T) {
	c := makeTestCertification(t)
	wp, err := gotpm.DecodePublic(c.WorkPublicArea)
	if err != nil {
		t.Fatal(err)
	}
	ap, err := gotpm.DecodePublic(c.AttestationPublicArea)
	if err != nil {
		t.Fatal(err)
	}
	// Use the backend's exact AK template. The public key and signed statement
	// remain the existing verifier fixture; this tests response plumbing only.
	ap.Attributes = deviceAKTemplate().Attributes
	ap.RSAParameters.Sign = deviceAKTemplate().RSAParameters.Sign
	aa, err := ap.Encode()
	if err != nil {
		t.Fatal(err)
	}
	c.AttestationPublicArea = aa
	body, err := tpmutil.Pack(tpmutil.U16Bytes(c.AttestationStatement), tpmutil.RawBytes(c.AttestationSignature))
	if err != nil {
		t.Fatal(err)
	}
	w := &deviceWire{t: t, codes: []uint32{0x173, 0x173, 0x148}, responses: [][]byte{devicePublicResponse(t, ap), devicePublicResponse(t, wp), deviceResponse(0, true, body)}}
	signer := &deviceSigner{rw: w, work: 0x81010020, public: c.WorkPublicKey}
	proof, err := signer.CertifyWorkKey("WorldLand-TPM-AIK", false, c.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyKeyCertification(proof); err != nil {
		t.Fatal(err)
	}
	if len(w.codes) != 0 {
		t.Fatal("missing TPM commands")
	}
}

func TestDeviceActivationPolicyAndSessionCleanup(t *testing.T) {
	c := makeTestCertification(t)
	ak := deviceAKTemplate()
	pub, _, err := ParsePublicArea(c.AttestationPublicArea)
	if err != nil {
		t.Fatal(err)
	}
	ak.RSAParameters.ModulusRaw = pub.(*rsa.PublicKey).N.FillBytes(make([]byte, 256))
	ek := deviceEKTemplate()
	ek.RSAParameters.ModulusRaw = append([]byte(nil), ak.RSAParameters.ModulusRaw...)
	start, _ := tpmutil.Pack(tpmutil.Handle(0x03000000), tpmutil.U16Bytes(make([]byte, 16)))
	policy, _ := tpmutil.Pack(tpmutil.U16Bytes(nil), gotpm.Ticket{Type: gotpm.TagAuthSecret, Hierarchy: gotpm.HandleEndorsement})
	secret := []byte("verifier-secret")
	activation, _ := tpmutil.Pack(tpmutil.U16Bytes(secret))
	for _, failPolicy := range []bool{false, true} {
		w := &deviceWire{t: t, codes: []uint32{0x173, 0x173, 0x176, 0x151}, responses: [][]byte{devicePublicResponse(t, ak), devicePublicResponse(t, ek), deviceResponse(0, false, start)}}
		if failPolicy {
			w.responses = append(w.responses, deviceResponse(0x101, false, nil))
		} else {
			w.responses = append(w.responses, deviceResponse(0, true, policy), deviceResponse(0, true, activation))
			w.codes = append(w.codes, 0x147)
		}
		w.codes = append(w.codes, 0x165)
		w.responses = append(w.responses, deviceResponse(0, false, nil))
		signer := &deviceSigner{rw: w, work: 0x81010020}
		got, err := signer.ActivateCredential("WorldLand-TPM-AIK", 0, []byte{1}, []byte{2})
		if failPolicy {
			if err == nil {
				t.Fatal("accepted failed policy")
			}
		} else if err != nil || !bytes.Equal(got, secret) {
			t.Fatalf("activation: %x %v", got, err)
		}
		if len(w.codes) != 0 {
			t.Fatal("policy session was not flushed")
		}
	}
}

func TestDeviceEKCertificateMustMatch(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := deviceEKTemplate()
	p.RSAParameters.ModulusRaw = key.N.FillBytes(make([]byte, 256))
	area, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{der, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})} {
		got, err := matchingEKCertificate(input, area)
		if err != nil || !bytes.Equal(got, der) {
			t.Fatalf("matching certificate: %v", err)
		}
	}
	for _, input := range [][]byte{nil, []byte("bad"), make([]byte, 65537), append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), []byte("trailing")...)} {
		if _, err := matchingEKCertificate(input, area); err == nil {
			t.Fatal("accepted malformed certificate")
		}
	}
	p.RSAParameters.ModulusRaw[0] ^= 1
	otherArea, _ := p.Encode()
	if _, err := matchingEKCertificate(der, otherArea); err == nil {
		t.Fatal("accepted another EK's certificate")
	}
}

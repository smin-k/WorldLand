package tpmregistry

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/crypto"
)

func gcpFixture(t *testing.T) (*Policy, *Evidence) {
	t.Helper()
	data, err := os.ReadFile("testdata/gcp/preflight.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		EnrollmentIdentity Evidence
		WorkPublicKey      string
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	e := &fixture.EnrollmentIdentity
	e.Version = EvidenceVersion
	e.WorkPublicKey, err = hex.DecodeString(fixture.WorkPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	e.VRFPublicKey = crypto.CompressPubkey(&key.PublicKey)
	e.Profile = []byte("gcp-preflight-test")
	intermediate, err := os.ReadFile("testdata/gcp/intermediate.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(intermediate)
	if block == nil {
		t.Fatal("missing intermediate")
	}
	e.EKIntermediatesDER = [][]byte{block.Bytes}
	p := &Policy{Version: EvidenceVersion, MaxEvidenceBytes: 1024 * 1024,
		Clock: func() time.Time { return time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC) }}
	if err := p.ConfigureCertificateProfile(CertificateProfileGCPCAS); err != nil {
		t.Fatal(err)
	}
	return p, e
}

func TestGCPCapturedEvidence(t *testing.T) {
	p, e := gcpFixture(t)
	if _, err := p.ValidateEvidence(big.NewInt(123), common.Address{}, e); err != nil {
		t.Fatal(err)
	}
	gcpDigest, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	p.CertificateProfile = ""
	manufacturerDigest, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if gcpDigest == manufacturerDigest {
		t.Fatal("profile absent from digest")
	}
	p.CertificateProfile = CertificateProfileManufacturer
	explicitDigest, err := p.Digest()
	if err != nil || explicitDigest != manufacturerDigest {
		t.Fatal("default manufacturer digest changed")
	}
	p.RequireEKCertificateOID = true
	if _, err := p.ValidateEvidence(big.NewInt(123), common.Address{}, e); err == nil {
		t.Fatal("manufacturer accepted missing EK OID")
	}
}

func TestGCPRejectInvalidEvidence(t *testing.T) {
	for _, name := range []string{"missing intermediate", "tampered leaf", "expired", "wrong root", "unknown policy", "OID override", "nil root"} {
		t.Run(name, func(t *testing.T) {
			p, e := gcpFixture(t)
			switch name {
			case "missing intermediate":
				e.EKIntermediatesDER = nil
			case "tampered leaf":
				e.EKCertificateDER[len(e.EKCertificateDER)-1] ^= 1
			case "expired":
				p.Clock = func() time.Time { return time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC) }
			case "wrong root":
				c, err := x509.ParseCertificate(e.EKIntermediatesDER[0])
				if err != nil {
					t.Fatal(err)
				}
				p.RootCertificates = []*x509.Certificate{c}
			case "unknown policy":
				p.CertificateProfile = "unknown"
			case "OID override":
				p.RequireEKCertificateOID = true
			case "nil root":
				p.RootCertificates = []*x509.Certificate{nil}
			}
			if _, err := p.ValidateEvidence(big.NewInt(123), common.Address{}, e); err == nil {
				t.Fatal("invalid evidence accepted")
			}
		})
	}
}

func TestGCPLeafConstraints(t *testing.T) {
	for _, name := range []string{"AK usage", "CA", "missing identity", "duplicate identity", "trailing bytes", "subject mismatch", "nonproduction", "negative project"} {
		t.Run(name, func(t *testing.T) {
			_, e := gcpFixture(t)
			cert, err := x509.ParseCertificate(e.EKCertificateDER)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "AK usage":
				cert.KeyUsage = x509.KeyUsageDigitalSignature
			case "CA":
				cert.IsCA = true
			case "missing identity":
				cert.Extensions = nil
			case "subject mismatch":
				cert.Subject.CommonName = "1"
			default:
				for i, ext := range cert.Extensions {
					if !ext.Id.Equal(gceInstanceOID) {
						continue
					}
					switch name {
					case "duplicate identity":
						cert.Extensions = append(cert.Extensions, pkix.Extension{Id: gceInstanceOID, Value: ext.Value})
					case "trailing bytes":
						cert.Extensions[i].Value = append(append([]byte{}, ext.Value...), 0)
					default:
						var info gceInstanceIdentity
						if _, err := asn1.Unmarshal(ext.Value, &info); err != nil {
							t.Fatal(err)
						}
						if name == "negative project" {
							info.ProjectNumber = -1
						} else {
							// Explicit production=false, all other optional security fields absent.
							info.Security = asn1.RawValue{FullBytes: []byte{0xa0, 7, 0x30, 5, 0xa1, 3, 1, 1, 0}}
						}
						cert.Extensions[i].Value, err = asn1.Marshal(info)
						if err != nil {
							t.Fatal(err)
						}
					}
					break
				}
			}
			if err := validateGCPEKCertificate(cert); err == nil {
				t.Fatal("invalid leaf accepted")
			}
		})
	}
}

func TestGCPCustomRootsRejected(t *testing.T) {
	p, _ := gcpFixture(t)
	if err := p.ConfigureCertificateProfile(CertificateProfileGCPCAS); err == nil {
		t.Fatal("custom roots accepted")
	}
}

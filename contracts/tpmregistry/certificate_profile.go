package tpmregistry

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
)

const (
	CertificateProfileManufacturer = "manufacturer"
	CertificateProfileGCPCAS       = "gcp-cas-v1"
)

// Source and immutable upstream revision are documented in docs/tpm-gcp.md.
//
//go:embed roots/gcp_ek_ak_ca_root.pem
var gcpRootPEM []byte

func pinnedGCPRoot() (*x509.Certificate, error) {
	block, rest := pem.Decode(gcpRootPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("tpmregistry: invalid embedded GCP root")
	}
	return x509.ParseCertificate(block.Bytes)
}

// ConfigureCertificateProfile is an explicit validator choice, never selected
// from claimant evidence. GCP supplies its own pinned root, not caller roots.
func (p *Policy) ConfigureCertificateProfile(profile string) error {
	if p == nil {
		return errors.New("tpmregistry: nil policy")
	}
	switch profile {
	case "", CertificateProfileManufacturer:
		p.CertificateProfile = CertificateProfileManufacturer
	case CertificateProfileGCPCAS:
		if len(p.RootCertificates) != 0 {
			return errors.New("tpmregistry: gcp-cas-v1 does not accept custom EK roots")
		}
		root, err := pinnedGCPRoot()
		if err != nil {
			return err
		}
		p.RootCertificates = []*x509.Certificate{root}
		p.RequireEKCertificateOID = false
		p.CertificateProfile = profile
	default:
		return fmt.Errorf("tpmregistry: unknown certificate profile %q", profile)
	}
	return p.validateCertificatePolicy()
}

func (p *Policy) validateCertificatePolicy() error {
	if p == nil || len(p.RootCertificates) == 0 {
		return errors.New("tpmregistry: policy has no EK roots")
	}
	for _, root := range p.RootCertificates {
		if root == nil {
			return errors.New("tpmregistry: nil EK root")
		}
	}
	switch p.CertificateProfile {
	case "", CertificateProfileManufacturer:
		return nil
	case CertificateProfileGCPCAS:
		root, err := pinnedGCPRoot()
		if err != nil {
			return err
		}
		if p.RequireEKCertificateOID || len(p.RootCertificates) != 1 || !bytes.Equal(p.RootCertificates[0].Raw, root.Raw) {
			return errors.New("tpmregistry: gcp-cas-v1 requires the pinned Google root and its dedicated EK checks")
		}
		return nil
	default:
		return fmt.Errorf("tpmregistry: unknown certificate profile %q", p.CertificateProfile)
	}
}

var gceInstanceOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 21}

type gceInstanceIdentity struct {
	Zone          string `asn1:"utf8"`
	ProjectNumber int64
	ProjectID     string `asn1:"utf8"`
	InstanceID    int64
	InstanceName  string `asn1:"utf8"`
	Security      asn1.RawValue
}

// This is an issuance identity check, NOT fresh VM/SEV attestation. Call only
// after x509 verification to the pinned root. AKs from the same CA are rejected.
func validateGCPEKCertificate(cert *x509.Certificate) error {
	key, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || key.N.BitLen() != 2048 || key.E != 65537 || cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage != x509.KeyUsageKeyEncipherment {
		return errors.New("tpmregistry: invalid GCP RSA2048 EK certificate constraints")
	}
	var extension []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(gceInstanceOID) {
			if extension != nil {
				return errors.New("tpmregistry: duplicate GCE instance identity")
			}
			extension = ext.Value
		}
	}
	if len(extension) == 0 {
		return errors.New("tpmregistry: missing GCE instance identity")
	}
	var info gceInstanceIdentity
	rest, err := asn1.Unmarshal(extension, &info)
	if err != nil || len(rest) != 0 {
		return errors.New("tpmregistry: malformed GCE instance identity")
	}
	// Reject extra outer fields which encoding/asn1 otherwise silently ignores.
	encoded, err := asn1.Marshal(info)
	if err != nil || !bytes.Equal(encoded, extension) {
		return errors.New("tpmregistry: noncanonical GCE instance identity")
	}
	if info.ProjectNumber <= 0 || info.InstanceID <= 0 || info.Zone == "" || info.ProjectID == "" || info.InstanceName == "" {
		return errors.New("tpmregistry: invalid GCE instance identifiers")
	}
	if cert.Subject.CommonName != strconv.FormatInt(info.InstanceID, 10) || len(cert.Subject.OrganizationalUnit) != 1 || cert.Subject.OrganizationalUnit[0] != info.ProjectID || len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "Google Compute Engine" || len(cert.Subject.Locality) != 1 || cert.Subject.Locality[0] != info.Zone {
		return errors.New("tpmregistry: GCE subject and instance identity mismatch")
	}
	if info.Security.Class != 2 || info.Security.Tag != 0 || !info.Security.IsCompound {
		return errors.New("tpmregistry: missing GCE security properties")
	}
	var fields []asn1.RawValue
	rest, err = asn1.Unmarshal(info.Security.Bytes, &fields)
	if err != nil || len(rest) != 0 {
		return errors.New("tpmregistry: malformed GCE security properties")
	}
	production, lastTag := false, -1
	for _, field := range fields {
		if field.Class != 2 || !field.IsCompound || field.Tag <= lastTag || field.Tag > 5 {
			return errors.New("tpmregistry: invalid GCE security property tag")
		}
		lastTag = field.Tag
		if field.Tag == 0 {
			var version int64
			rest, err = asn1.Unmarshal(field.Bytes, &version)
			if err != nil || len(rest) != 0 || version < 0 {
				return errors.New("tpmregistry: invalid GCE security version")
			}
		} else {
			var value bool
			rest, err = asn1.Unmarshal(field.Bytes, &value)
			if err != nil || len(rest) != 0 {
				return errors.New("tpmregistry: invalid GCE security flag")
			}
			if field.Tag == 1 {
				production = value
			}
		}
	}
	if !production {
		return errors.New("tpmregistry: GCE certificate is not production-issued")
	}
	return nil
}

package tpmregistry

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/crypto"
	"github.com/cryptoecc/WorldLand/crypto/tpmwork"
	gotpm "github.com/google/go-tpm/tpm2"
)

// enrollmentRulesDigest separates approvals made under the canonical EK/VRF
// rules from approvals made by the earlier, permissive implementation. Existing
// deployments must explicitly replace their policy digest; legacy registrations
// require a migration or a fresh registry, not an accept-old-nullifiers fallback.
var enrollmentRulesDigest = crypto.Keccak256Hash([]byte("WorldLand TPM enrollment rules v2: canonical RSA2048 EK; compressed secp256k1 VRF"))

// CanonicalEKName implements the paper's Name(EK_can) for the fixed RSA-2048 EK
// profile: SHA-256 Name, fixedTPM/fixedParent/sensitiveDataOrigin/adminWithPolicy/
// restricted/decrypt, the standard endorsement PolicySecret policy, AES-128-CFB,
// NULL signing scheme and exponent 65537 (canonically encoded as zero).
//
// Only the two equivalent encodings of exponent 65537 are normalized. Other
// public-template changes are rejected. This function does not authenticate a
// TPM: enrollment must also match the RSA key to a manufacturer-validated EK
// certificate and complete credential activation. In particular, a submitted
// EK Name is never accepted as evidence of its own canonicality.
func CanonicalEKName(publicArea []byte) ([]byte, error) {
	public, _, err := tpmwork.ParsePublicArea(publicArea)
	if err != nil {
		return nil, fmt.Errorf("tpmregistry: parse canonical EK: %w", err)
	}
	rsaPublic, ok := public.(*rsa.PublicKey)
	if !ok || rsaPublic.N.BitLen() != 2048 || rsaPublic.N.Bit(0) != 1 || rsaPublic.E != 65537 {
		return nil, errors.New("tpmregistry: EK must use the RSA-2048 exponent-65537 profile")
	}
	canonical := gotpm.Public{
		Type: gotpm.AlgRSA, NameAlg: gotpm.AlgSHA256,
		Attributes: gotpm.FlagFixedTPM | gotpm.FlagFixedParent | gotpm.FlagSensitiveDataOrigin |
			gotpm.FlagAdminWithPolicy | gotpm.FlagRestricted | gotpm.FlagDecrypt,
		// PolicySecret(TPM_RH_ENDORSEMENT), SHA-256, empty policyRef.
		AuthPolicy: common.FromHex("837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa"),
		RSAParameters: &gotpm.RSAParams{
			Symmetric: &gotpm.SymScheme{Alg: gotpm.AlgAES, KeyBits: 128, Mode: gotpm.AlgCFB},
			KeyBits:   2048, ExponentRaw: 0,
			ModulusRaw: rsaPublic.N.FillBytes(make([]byte, 256)),
		},
	}
	encoded, err := canonical.Encode()
	if err != nil {
		return nil, fmt.Errorf("tpmregistry: encode canonical EK: %w", err)
	}
	if !bytes.Equal(publicArea, encoded) {
		canonical.RSAParameters.ExponentRaw = 65537
		explicitExponent, err := canonical.Encode()
		if err != nil {
			return nil, fmt.Errorf("tpmregistry: encode explicit EK exponent: %w", err)
		}
		if !bytes.Equal(publicArea, explicitExponent) {
			return nil, errors.New("tpmregistry: EK public area does not match the canonical RSA-2048 profile")
		}
	}
	_, name, err := tpmwork.ParsePublicArea(encoded)
	return name, err
}

// CanonicalVRFPublicKey accepts the documented uncompressed enrollment key or
// the compressed consensus key and returns the unique compressed encoding.
// Evidence commitments retain their original bytes; only the registered key
// identity is normalized so it matches the VCT header's 33-byte public key.
func CanonicalVRFPublicKey(encoded []byte) ([]byte, error) {
	var public *ecdsa.PublicKey
	var err error
	switch len(encoded) {
	case 33:
		public, err = crypto.DecompressPubkey(encoded)
	case 65:
		public, err = crypto.UnmarshalPubkey(encoded)
	default:
		return nil, errors.New("tpmregistry: VRF public key must be compressed or uncompressed secp256k1")
	}
	if err != nil {
		return nil, fmt.Errorf("tpmregistry: invalid VRF public key: %w", err)
	}
	return crypto.CompressPubkey(public), nil
}

// VRFKeyHash returns the key commitment consumed by VCT consensus validation.
func VRFKeyHash(encoded []byte) (common.Hash, error) {
	canonical, err := CanonicalVRFPublicKey(encoded)
	if err != nil {
		return common.Hash{}, err
	}
	return crypto.Keccak256Hash(canonical), nil
}

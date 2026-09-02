//go:build windows

package tpmwork

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"unsafe"

	gotpm "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"golang.org/x/sys/windows"
)

// EnrollmentIdentity reads the standard RSA EK and a persisted AIK. Creating
// the AIK is explicit; the EK, hierarchy and certificate NV index are read only.
func (s *PlatformSigner) EnrollmentIdentity(attestationKeyName string, create bool, ekHandle, ekCertificateIndex uint32) (*EnrollmentIdentity, error) {
	if ekHandle == 0 {
		ekHandle = DefaultRSAEKHandle
	}
	if ekCertificateIndex == 0 {
		ekCertificateIndex = DefaultRSAEKCertificateIndex
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.provider == 0 {
		return nil, errors.New("tpmwork: signer is closed")
	}
	attestationKey, err := openPlatformAttestationKey(s.provider, attestationKeyName, create)
	if err != nil {
		return nil, err
	}
	defer procFreeObject.Call(attestationKey)
	attestationHandle, err := ncryptUint32Property(attestationKey, pcpPlatformHandleProperty)
	if err != nil {
		return nil, err
	}
	attestationPublic, err := exportRSAPublicKey(attestationKey)
	if err != nil {
		return nil, err
	}
	attestationDER, err := x509.MarshalPKIXPublicKey(attestationPublic)
	if err != nil {
		return nil, fmt.Errorf("tpmwork: encode attestation public key: %w", err)
	}

	tbsContext, err := ncryptUintptrProperty(s.provider, pcpPlatformHandleProperty)
	if err != nil {
		return nil, err
	}
	rw := &providerTPMChannel{context: tbsContext}
	ekPublic, ekName, _, err := gotpm.ReadPublic(rw, tpmutil.Handle(ekHandle))
	if err != nil {
		return nil, fmt.Errorf("tpmwork: read RSA EK public area at 0x%08x: %w", ekHandle, err)
	}
	ekPublicArea, err := ekPublic.Encode()
	if err != nil {
		return nil, fmt.Errorf("tpmwork: encode RSA EK public area: %w", err)
	}
	attestationArea, attestationName, _, err := gotpm.ReadPublic(rw, tpmutil.Handle(attestationHandle))
	if err != nil {
		return nil, fmt.Errorf("tpmwork: read attestation public area: %w", err)
	}
	attestationPublicArea, err := attestationArea.Encode()
	if err != nil {
		return nil, fmt.Errorf("tpmwork: encode attestation public area: %w", err)
	}
	ekCertificate, err := gotpm.NVReadEx(
		rw,
		tpmutil.Handle(ekCertificateIndex),
		tpmutil.Handle(ekCertificateIndex),
		"",
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("tpmwork: read RSA EK certificate at 0x%08x: %w", ekCertificateIndex, err)
	}
	return &EnrollmentIdentity{
		EKCertificateDER:      append([]byte(nil), ekCertificate...),
		EKPublicArea:          ekPublicArea,
		EKName:                append([]byte(nil), ekName...),
		AttestationPublicKey:  attestationDER,
		AttestationPublicArea: attestationPublicArea,
		AttestationName:       append([]byte(nil), attestationName...),
	}, nil
}

// ActivateCredential proves that the named AIK and standard EK are available
// to the same TPM. The EK authorization uses the standard endorsement policy.
func (s *PlatformSigner) ActivateCredential(attestationKeyName string, ekHandle uint32, credentialBlob, encryptedSecret []byte) ([]byte, error) {
	if ekHandle == 0 {
		ekHandle = DefaultRSAEKHandle
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.provider == 0 {
		return nil, errors.New("tpmwork: signer is closed")
	}
	keyName16, _ := windows.UTF16PtrFromString(attestationKeyName)
	var attestationKey uintptr
	status, _, _ := procOpenKey.Call(s.provider, uintptr(unsafe.Pointer(&attestationKey)), uintptr(unsafe.Pointer(keyName16)), 0, ncryptSilentFlag)
	if status != 0 {
		return nil, ncryptError("open TPM attestation key", status)
	}
	defer procFreeObject.Call(attestationKey)
	attestationHandle, err := ncryptUint32Property(attestationKey, pcpPlatformHandleProperty)
	if err != nil {
		return nil, err
	}

	tbsContext, err := ncryptUintptrProperty(s.provider, pcpPlatformHandleProperty)
	if err != nil {
		return nil, err
	}
	rw := &providerTPMChannel{context: tbsContext}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("tpmwork: create policy nonce: %w", err)
	}
	session, _, err := gotpm.StartAuthSession(
		rw, gotpm.HandleNull, gotpm.HandleNull, nonce, nil,
		gotpm.SessionPolicy, gotpm.AlgNull, gotpm.AlgSHA256,
	)
	if err != nil {
		return nil, fmt.Errorf("tpmwork: start EK policy session: %w", err)
	}
	defer gotpm.FlushContext(rw, session)
	_, _, err = gotpm.PolicySecret(
		rw,
		gotpm.HandleEndorsement,
		gotpm.AuthCommand{Session: gotpm.HandlePasswordSession, Attributes: gotpm.AttrContinueSession},
		session,
		nil, nil, nil, 0,
	)
	if err != nil {
		return nil, fmt.Errorf("tpmwork: satisfy EK endorsement policy: %w", err)
	}
	activated, err := gotpm.ActivateCredentialUsingAuth(
		rw,
		[]gotpm.AuthCommand{
			{Session: gotpm.HandlePasswordSession, Attributes: gotpm.AttrContinueSession},
			{Session: session, Attributes: gotpm.AttrContinueSession},
		},
		tpmutil.Handle(attestationHandle),
		tpmutil.Handle(ekHandle),
		credentialBlob,
		encryptedSecret,
	)
	if err != nil {
		return nil, fmt.Errorf("tpmwork: activate credential: %w", err)
	}
	return activated, nil
}

// providerTPMChannel adapts the Platform Crypto Provider's TBS context to the
// command/response interface used by go-tpm. This is necessary because NCrypt
// transient handles are scoped to this resource-manager context.
type providerTPMChannel struct {
	context  uintptr
	response []byte
}

func (channel *providerTPMChannel) Write(command []byte) (int, error) {
	if len(channel.response) != 0 {
		return 0, errors.New("tpmwork: previous TPM response was not consumed")
	}
	response, err := submitTPMCommand(channel.context, command)
	if err != nil {
		return 0, err
	}
	channel.response = response
	return len(command), nil
}

func (channel *providerTPMChannel) Read(output []byte) (int, error) {
	if len(channel.response) == 0 {
		return 0, io.EOF
	}
	count := copy(output, channel.response)
	channel.response = channel.response[count:]
	return count, nil
}

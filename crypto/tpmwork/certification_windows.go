//go:build windows

package tpmwork

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	rsaAlgorithm              = "RSA"
	rsaPublicBlob             = "RSAPUBLICBLOB"
	rsaPublicMagic            = 0x31415352 // BCRYPT_RSAPUBLIC_MAGIC ("RSA1")
	ncryptLengthProperty      = "Length"
	pcpPlatformHandleProperty = "PCP_PLATFORMHANDLE"
	pcpKeyUsagePolicyProperty = "PCP_KEY_USAGE_POLICY"
	pcpRSASchemeProperty      = "PCP_RSA_SCHEME"
	pcpRSASchemeHashProperty  = "PCP_RSA_SCHEME_HASH_ALG"
	pcpIdentityKey            = 0x00000008
	ncryptSilentFlag          = 0x00000040

	tpmSTNoSessions = 0x8001
	tpmSTSessions   = 0x8002
	tpmRSPassword   = 0x40000009
	tpmCCCertify    = 0x00000148
	tpmCCReadPublic = 0x00000173

	tbsLocalityZero   = 0
	tbsPriorityNormal = 200
	maxTPMResponse    = 4096
)

var (
	procSetProperty = ncrypt.NewProc("NCryptSetProperty")
	tbs             = windows.NewLazySystemDLL("tbs.dll")
	procTBSSubmit   = tbs.NewProc("Tbsip_Submit_Command")
)

// CertifyWorkKey creates or opens a restricted RSA attestation key and asks
// the physical TPM to certify the work key with a caller-provided challenge.
// The named AIK is persisted when create is true; no key is deleted or TPM
// hierarchy cleared by this operation.
func (s *PlatformSigner) CertifyWorkKey(attestationKeyName string, create bool, challenge []byte) (*KeyCertification, error) {
	if attestationKeyName == "" {
		return nil, errors.New("tpmwork: attestation key name is empty")
	}
	if len(challenge) == 0 || len(challenge) > 0xffff {
		return nil, errors.New("tpmwork: attestation challenge must contain 1..65535 bytes")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == 0 || s.provider == 0 {
		return nil, errors.New("tpmwork: signer is closed")
	}

	attestationKey, err := openPlatformAttestationKey(s.provider, attestationKeyName, create)
	if err != nil {
		return nil, err
	}
	defer procFreeObject.Call(attestationKey)

	tbsContext, err := ncryptUintptrProperty(s.provider, pcpPlatformHandleProperty)
	if err != nil {
		return nil, err
	}
	workHandle, err := ncryptUint32Property(s.key, pcpPlatformHandleProperty)
	if err != nil {
		return nil, err
	}
	attestationHandle, err := ncryptUint32Property(attestationKey, pcpPlatformHandleProperty)
	if err != nil {
		return nil, err
	}

	workPublicArea, err := readTPMPublicArea(tbsContext, workHandle)
	if err != nil {
		return nil, fmt.Errorf("tpmwork: read work public area: %w", err)
	}
	attestationPublicArea, err := readTPMPublicArea(tbsContext, attestationHandle)
	if err != nil {
		return nil, fmt.Errorf("tpmwork: read attestation public area: %w", err)
	}
	attestationPublic, err := exportRSAPublicKey(attestationKey)
	if err != nil {
		return nil, err
	}
	attestationDER, err := x509.MarshalPKIXPublicKey(attestationPublic)
	if err != nil {
		return nil, fmt.Errorf("tpmwork: encode attestation public key: %w", err)
	}

	command := buildCertifyCommand(workHandle, attestationHandle, challenge)
	response, err := submitTPMCommand(tbsContext, command)
	if err != nil {
		return nil, fmt.Errorf("tpmwork: certify work key: %w", err)
	}
	statement, signature, err := parseCertifyResponse(response)
	if err != nil {
		return nil, err
	}
	certification := &KeyCertification{
		Version:               CertificationVersion,
		Challenge:             append([]byte(nil), challenge...),
		WorkPublicKey:         append([]byte(nil), s.public...),
		WorkPublicArea:        workPublicArea,
		AttestationPublicKey:  attestationDER,
		AttestationPublicArea: attestationPublicArea,
		AttestationStatement:  statement,
		AttestationSignature:  signature,
	}
	if err := VerifyKeyCertification(certification); err != nil {
		return nil, fmt.Errorf("tpmwork: locally verify certification: %w", err)
	}
	return certification, nil
}

func openPlatformAttestationKey(provider uintptr, keyName string, create bool) (uintptr, error) {
	keyName16, _ := windows.UTF16PtrFromString(keyName)
	var key uintptr
	status, _, _ := procOpenKey.Call(provider, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(keyName16)), 0, ncryptSilentFlag)
	if status == 0 {
		usage, err := ncryptUint32Property(key, pcpKeyUsagePolicyProperty)
		if err != nil || usage&pcpIdentityKey == 0 {
			procFreeObject.Call(key)
			return 0, errors.New("tpmwork: named attestation key is not a restricted TPM identity key")
		}
		return key, nil
	}
	if !create {
		return 0, ncryptError("open TPM attestation key", status)
	}
	algorithm, _ := windows.UTF16PtrFromString(rsaAlgorithm)
	status, _, _ = procCreatePersistedKey.Call(provider, uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(algorithm)), uintptr(unsafe.Pointer(keyName16)), 0, ncryptSilentFlag)
	if status != 0 {
		return 0, ncryptError("create TPM attestation key", status)
	}
	failed := true
	defer func() {
		if failed && key != 0 {
			procFreeObject.Call(key)
		}
	}()
	properties := []struct {
		name  string
		value uint32
	}{
		{ncryptLengthProperty, 2048},
		{pcpKeyUsagePolicyProperty, pcpIdentityKey},
		{pcpRSASchemeProperty, tpmAlgRSASSA},
		{pcpRSASchemeHashProperty, tpmAlgSHA256},
	}
	for _, property := range properties {
		if err := ncryptSetUint32Property(key, property.name, property.value); err != nil {
			return 0, err
		}
	}
	status, _, _ = procFinalizeKey.Call(key, ncryptSilentFlag)
	if status != 0 {
		return 0, ncryptError("finalize TPM attestation key", status)
	}
	failed = false
	return key, nil
}

func ncryptSetUint32Property(handle uintptr, name string, value uint32) error {
	property, _ := windows.UTF16PtrFromString(name)
	status, _, _ := procSetProperty.Call(handle, uintptr(unsafe.Pointer(property)), uintptr(unsafe.Pointer(&value)), unsafe.Sizeof(value), 0)
	if status != 0 {
		return ncryptError("set "+name, status)
	}
	return nil
}

func ncryptUint32Property(handle uintptr, name string) (uint32, error) {
	property, _ := windows.UTF16PtrFromString(name)
	var value uint32
	var size uint32
	status, _, _ := procGetProperty.Call(handle, uintptr(unsafe.Pointer(property)), uintptr(unsafe.Pointer(&value)), unsafe.Sizeof(value), uintptr(unsafe.Pointer(&size)), 0)
	if status != 0 {
		return 0, ncryptError("read "+name, status)
	}
	if size != uint32(unsafe.Sizeof(value)) {
		return 0, fmt.Errorf("tpmwork: %s returned %d bytes, want %d", name, size, unsafe.Sizeof(value))
	}
	return value, nil
}

func ncryptUintptrProperty(handle uintptr, name string) (uintptr, error) {
	property, _ := windows.UTF16PtrFromString(name)
	var value uintptr
	var size uint32
	status, _, _ := procGetProperty.Call(handle, uintptr(unsafe.Pointer(property)), uintptr(unsafe.Pointer(&value)), unsafe.Sizeof(value), uintptr(unsafe.Pointer(&size)), 0)
	if status != 0 {
		return 0, ncryptError("read "+name, status)
	}
	if size != uint32(unsafe.Sizeof(value)) {
		return 0, fmt.Errorf("tpmwork: %s returned %d bytes, want %d", name, size, unsafe.Sizeof(value))
	}
	return value, nil
}

func exportRSAPublicKey(key uintptr) (*rsa.PublicKey, error) {
	blobType, _ := windows.UTF16PtrFromString(rsaPublicBlob)
	var size uint32
	status, _, _ := procExportKey.Call(key, 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0, uintptr(unsafe.Pointer(&size)), 0)
	if status != 0 {
		return nil, ncryptError("size TPM attestation public key", status)
	}
	blob := make([]byte, size)
	status, _, _ = procExportKey.Call(key, 0, uintptr(unsafe.Pointer(blobType)), 0, uintptr(unsafe.Pointer(&blob[0])), uintptr(len(blob)), uintptr(unsafe.Pointer(&size)), 0)
	if status != 0 {
		return nil, ncryptError("export TPM attestation public key", status)
	}
	blob = blob[:size]
	if len(blob) < 24 || binary.LittleEndian.Uint32(blob[:4]) != rsaPublicMagic {
		return nil, errors.New("tpmwork: unexpected RSA public blob")
	}
	exponentSize := int(binary.LittleEndian.Uint32(blob[8:12]))
	modulusSize := int(binary.LittleEndian.Uint32(blob[12:16]))
	if exponentSize <= 0 || modulusSize <= 0 || len(blob) != 24+exponentSize+modulusSize {
		return nil, errors.New("tpmwork: malformed RSA public blob")
	}
	exponent := new(big.Int).SetBytes(blob[24 : 24+exponentSize])
	if !exponent.IsInt64() || exponent.Sign() <= 0 {
		return nil, errors.New("tpmwork: invalid RSA exponent")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(blob[24+exponentSize:]),
		E: int(exponent.Int64()),
	}, nil
}

func buildReadPublicCommand(handle uint32) []byte {
	command := make([]byte, 14)
	binary.BigEndian.PutUint16(command[0:2], tpmSTNoSessions)
	binary.BigEndian.PutUint32(command[2:6], uint32(len(command)))
	binary.BigEndian.PutUint32(command[6:10], tpmCCReadPublic)
	binary.BigEndian.PutUint32(command[10:14], handle)
	return command
}

func readTPMPublicArea(context uintptr, handle uint32) ([]byte, error) {
	response, err := submitTPMCommand(context, buildReadPublicCommand(handle))
	if err != nil {
		return nil, err
	}
	if len(response) < 12 || binary.BigEndian.Uint16(response[:2]) != tpmSTNoSessions {
		return nil, errors.New("unexpected TPM2_ReadPublic response")
	}
	publicSize := int(binary.BigEndian.Uint16(response[10:12]))
	if publicSize <= 0 || len(response) < 12+publicSize {
		return nil, errors.New("short TPM2_ReadPublic public area")
	}
	return append([]byte(nil), response[12:12+publicSize]...), nil
}

func buildCertifyCommand(objectHandle, signingHandle uint32, challenge []byte) []byte {
	const passwordSessionSize = 9
	totalSize := 10 + 8 + 4 + 2*passwordSessionSize + 2 + len(challenge) + 2
	var command bytes.Buffer
	_ = binary.Write(&command, binary.BigEndian, uint16(tpmSTSessions))
	_ = binary.Write(&command, binary.BigEndian, uint32(totalSize))
	_ = binary.Write(&command, binary.BigEndian, uint32(tpmCCCertify))
	_ = binary.Write(&command, binary.BigEndian, objectHandle)
	_ = binary.Write(&command, binary.BigEndian, signingHandle)
	_ = binary.Write(&command, binary.BigEndian, uint32(2*passwordSessionSize))
	for i := 0; i < 2; i++ {
		_ = binary.Write(&command, binary.BigEndian, uint32(tpmRSPassword))
		_ = binary.Write(&command, binary.BigEndian, uint16(0))
		command.WriteByte(0)
		_ = binary.Write(&command, binary.BigEndian, uint16(0))
	}
	_ = binary.Write(&command, binary.BigEndian, uint16(len(challenge)))
	command.Write(challenge)
	_ = binary.Write(&command, binary.BigEndian, uint16(tpmAlgNull))
	return command.Bytes()
}

func submitTPMCommand(context uintptr, command []byte) ([]byte, error) {
	response := make([]byte, maxTPMResponse)
	responseSize := uint32(len(response))
	result, _, _ := procTBSSubmit.Call(
		context,
		tbsLocalityZero,
		tbsPriorityNormal,
		uintptr(unsafe.Pointer(&command[0])),
		uintptr(len(command)),
		uintptr(unsafe.Pointer(&response[0])),
		uintptr(unsafe.Pointer(&responseSize)),
	)
	runtime.KeepAlive(command)
	if result != 0 {
		return nil, fmt.Errorf("TBS status 0x%08x", uint32(result))
	}
	if responseSize > uint32(len(response)) || responseSize < 10 {
		return nil, errors.New("invalid TBS response size")
	}
	response = response[:responseSize]
	declaredSize := binary.BigEndian.Uint32(response[2:6])
	if declaredSize != responseSize {
		return nil, fmt.Errorf("TPM response size is %d, declared %d", responseSize, declaredSize)
	}
	if code := binary.BigEndian.Uint32(response[6:10]); code != 0 {
		return nil, fmt.Errorf("TPM response code 0x%08x", code)
	}
	return response, nil
}

func parseCertifyResponse(response []byte) ([]byte, []byte, error) {
	if len(response) < 14 || binary.BigEndian.Uint16(response[:2]) != tpmSTSessions {
		return nil, nil, errors.New("tpmwork: unexpected TPM2_Certify response")
	}
	parameterSize := int(binary.BigEndian.Uint32(response[10:14]))
	if parameterSize <= 2 || len(response) < 14+parameterSize {
		return nil, nil, errors.New("tpmwork: short TPM2_Certify parameters")
	}
	parameters := response[14 : 14+parameterSize]
	statementSize := int(binary.BigEndian.Uint16(parameters[:2]))
	if statementSize <= 0 || len(parameters) < 2+statementSize {
		return nil, nil, errors.New("tpmwork: short TPM2B_ATTEST")
	}
	statement := append([]byte(nil), parameters[2:2+statementSize]...)
	signature := append([]byte(nil), parameters[2+statementSize:]...)
	if _, _, err := parseRSATPMTSignature(signature); err != nil {
		return nil, nil, err
	}
	return statement, signature, nil
}

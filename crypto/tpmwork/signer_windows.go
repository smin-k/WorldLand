//go:build windows

package tpmwork

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	platformProvider = "Microsoft Platform Crypto Provider"
	ecdsaP256        = "ECDSA_P256"
	eccPublicBlob    = "ECCPUBLICBLOB"
	eccPrivateBlob   = "ECCPRIVATEBLOB"
	ecdsaPublicP256  = 0x31534345 // BCRYPT_ECDSA_PUBLIC_P256_MAGIC ("ECS1")
)

var (
	ncrypt                  = windows.NewLazySystemDLL("ncrypt.dll")
	procOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	procCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
	procFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
	procGetProperty         = ncrypt.NewProc("NCryptGetProperty")
	procExportKey           = ncrypt.NewProc("NCryptExportKey")
	procSignHash            = ncrypt.NewProc("NCryptSignHash")
	procFreeObject          = ncrypt.NewProc("NCryptFreeObject")
)

// PlatformSigner signs with a persisted key in the Windows TPM platform KSP.
// Calls are serialized because many TPM providers expose a single command
// queue; the benchmark can deliberately open multiple handles to test whether
// the physical device permits aggregate parallelism.
type PlatformSigner struct {
	provider uintptr
	key      uintptr
	public   []byte
	mu       sync.Mutex
}

// OpenPlatformSigner opens keyName from the Microsoft Platform Crypto Provider.
// If create is true, a missing non-exportable P-256 key is created in the TPM.
func OpenPlatformSigner(keyName string, create bool) (*PlatformSigner, error) {
	if keyName == "" {
		return nil, fmt.Errorf("tpmwork: key name is empty")
	}
	providerName, _ := windows.UTF16PtrFromString(platformProvider)
	var provider uintptr
	if status, _, _ := procOpenStorageProvider.Call(uintptr(unsafe.Pointer(&provider)), uintptr(unsafe.Pointer(providerName)), 0); status != 0 {
		return nil, ncryptError("open platform provider", status)
	}
	s := &PlatformSigner{provider: provider}
	keyName16, _ := windows.UTF16PtrFromString(keyName)
	status, _, _ := procOpenKey.Call(provider, uintptr(unsafe.Pointer(&s.key)), uintptr(unsafe.Pointer(keyName16)), 0, 0)
	if status != 0 {
		if !create {
			s.Close()
			return nil, ncryptError("open TPM work key", status)
		}
		algorithm, _ := windows.UTF16PtrFromString(ecdsaP256)
		status, _, _ = procCreatePersistedKey.Call(provider, uintptr(unsafe.Pointer(&s.key)), uintptr(unsafe.Pointer(algorithm)), uintptr(unsafe.Pointer(keyName16)), 0, 0)
		if status != 0 {
			s.Close()
			return nil, ncryptError("create TPM work key", status)
		}
		if status, _, _ = procFinalizeKey.Call(s.key, 0); status != 0 {
			s.Close()
			return nil, ncryptError("finalize TPM work key", status)
		}
	}
	public, err := exportPublicKey(s.key)
	if err != nil {
		s.Close()
		return nil, err
	}
	s.public = public
	runtime.SetFinalizer(s, func(s *PlatformSigner) { _ = s.Close() })
	return s, nil
}

func (s *PlatformSigner) PublicKey() []byte {
	return append([]byte(nil), s.public...)
}

func (s *PlatformSigner) SignDigest(digest []byte) ([]byte, error) {
	if len(digest) != DigestSize {
		return nil, fmt.Errorf("tpmwork: digest must be %d bytes", DigestSize)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == 0 {
		return nil, fmt.Errorf("tpmwork: signer is closed")
	}
	var size uint32
	status, _, _ := procSignHash.Call(s.key, 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)), 0, 0, uintptr(unsafe.Pointer(&size)), 0)
	if status != 0 {
		return nil, ncryptError("size TPM work signature", status)
	}
	signature := make([]byte, size)
	status, _, _ = procSignHash.Call(s.key, 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)), uintptr(unsafe.Pointer(&signature[0])), uintptr(len(signature)), uintptr(unsafe.Pointer(&size)), 0)
	if status != 0 {
		return nil, ncryptError("sign TPM work digest", status)
	}
	signature = signature[:size]
	if len(signature) != SignatureSize {
		return nil, fmt.Errorf("tpmwork: platform provider returned %d signature bytes, want %d", len(signature), SignatureSize)
	}
	return NormalizeSignature(signature)
}

// PrivateKeyExportBlocked probes only the size-query form of private export;
// it never requests or returns private key bytes. A non-zero NCrypt status
// means the platform provider refused the private-blob export operation.
func (s *PlatformSigner) PrivateKeyExportBlocked() (bool, uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == 0 {
		return true, 0xffffffff
	}
	blobType, _ := windows.UTF16PtrFromString(eccPrivateBlob)
	var size uint32
	status, _, _ := procExportKey.Call(s.key, 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0, uintptr(unsafe.Pointer(&size)), 0)
	return status != 0, uint32(status)
}

// PrivateKeyExportPolicy returns the NCrypt Export Policy bitmask. Zero means
// neither wrapped nor plaintext private-key export is permitted.
func (s *PlatformSigner) PrivateKeyExportPolicy() (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == 0 {
		return 0, fmt.Errorf("tpmwork: signer is closed")
	}
	property, _ := windows.UTF16PtrFromString("Export Policy")
	var policy uint32
	var size uint32
	status, _, _ := procGetProperty.Call(s.key, uintptr(unsafe.Pointer(property)), uintptr(unsafe.Pointer(&policy)), unsafe.Sizeof(policy), uintptr(unsafe.Pointer(&size)), 0)
	if status != 0 {
		return 0, ncryptError("read TPM work-key export policy", status)
	}
	return policy, nil
}

func (s *PlatformSigner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	runtime.SetFinalizer(s, nil)
	if s.key != 0 {
		procFreeObject.Call(s.key)
		s.key = 0
	}
	if s.provider != 0 {
		procFreeObject.Call(s.provider)
		s.provider = 0
	}
	return nil
}

func exportPublicKey(key uintptr) ([]byte, error) {
	blobType, _ := windows.UTF16PtrFromString(eccPublicBlob)
	var size uint32
	status, _, _ := procExportKey.Call(key, 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0, uintptr(unsafe.Pointer(&size)), 0)
	if status != 0 {
		return nil, ncryptError("size TPM public key", status)
	}
	blob := make([]byte, size)
	status, _, _ = procExportKey.Call(key, 0, uintptr(unsafe.Pointer(blobType)), 0, uintptr(unsafe.Pointer(&blob[0])), uintptr(len(blob)), uintptr(unsafe.Pointer(&size)), 0)
	if status != 0 {
		return nil, ncryptError("export TPM public key", status)
	}
	blob = blob[:size]
	if len(blob) != 8+2*32 || binary.LittleEndian.Uint32(blob[:4]) != ecdsaPublicP256 || binary.LittleEndian.Uint32(blob[4:8]) != 32 {
		return nil, fmt.Errorf("tpmwork: unexpected ECC public blob")
	}
	public := make([]byte, PublicKeySize)
	public[0] = 4
	copy(public[1:33], blob[8:40])
	copy(public[33:], blob[40:72])
	return public, nil
}

func ncryptError(operation string, status uintptr) error {
	return fmt.Errorf("tpmwork: %s failed with NCrypt status 0x%08x", operation, uint32(status))
}

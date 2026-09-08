//go:build linux

package tpmwork

import (
	"fmt"
	"os"

	gotpm "github.com/google/go-tpm/tpm2"
)

// PlatformSigner uses the Linux kernel TPM resource manager.
type PlatformSigner = deviceSigner

// OpenPlatformSigner opens a persistent TPM key. Creation is opt-in and never
// evicts an existing object. See docs/tpm-linux.md for names and provisioning.
func OpenPlatformSigner(keyName string, create bool) (*PlatformSigner, error) {
	handle, err := linuxKeyHandle(keyName, false)
	if err != nil {
		return nil, err
	}
	path := os.Getenv("WORLDLAND_TPM_DEVICE")
	if path == "" {
		path = "/dev/tpmrm0"
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("tpmwork: TPM device: %w", err)
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return nil, fmt.Errorf("tpmwork: %s is not a TPM character device", path)
	}
	rw, err := gotpm.OpenTPM(path)
	if err != nil {
		return nil, fmt.Errorf("tpmwork: open Linux TPM: %w", err)
	}
	signer, err := openDeviceSigner(rw, handle, create, os.Getenv("WORLDLAND_TPM_EK_CERT"))
	if err != nil {
		rw.Close()
		return nil, err
	}
	return signer, nil
}

//go:build !windows && !linux

package tpmwork

import "fmt"

// OpenPlatformSigner is supported on Windows and Linux only.
func OpenPlatformSigner(keyName string, create bool) (Signer, error) {
	return nil, fmt.Errorf("tpmwork: platform TPM provider requires Windows or Linux")
}

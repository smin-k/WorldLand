//go:build !windows

package tpmwork

import "fmt"

// OpenPlatformSigner is only available through the Windows platform KSP in
// this prototype. Linux TPM2-TSS support can implement the same Signer API.
func OpenPlatformSigner(keyName string, create bool) (Signer, error) {
	return nil, fmt.Errorf("tpmwork: Windows platform TPM provider is unavailable on this operating system")
}

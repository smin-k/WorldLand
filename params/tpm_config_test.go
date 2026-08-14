package params

import (
	"math/big"
	"testing"
)

func TestTPMGatedForkRequiresVCT(t *testing.T) {
	config := *AllEthashProtocolChanges
	config.TPMGatedBlock = big.NewInt(10)
	config.VCTBlock = nil
	if err := config.CheckConfigForkOrder(); err == nil {
		t.Fatal("TPM-gated fork without VCT fork accepted")
	}

	config.VCTBlock = big.NewInt(5)
	if err := config.CheckConfigForkOrder(); err != nil {
		t.Fatalf("ordered VCT and TPM-gated forks rejected: %v", err)
	}
	if config.IsTPMGated(big.NewInt(9)) {
		t.Fatal("TPM-gated fork active too early")
	}
	if !config.IsTPMGated(big.NewInt(10)) {
		t.Fatal("TPM-gated fork inactive at activation block")
	}
}

//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vct

import (
	"math/big"
	"testing"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/core/rawdb"
	"github.com/cryptoecc/WorldLand/core/state"
	"github.com/cryptoecc/WorldLand/crypto"
)

func TestVerifyTPMRegistration(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	st, err := state.New(common.Hash{}, state.NewDatabase(db), nil)
	if err != nil {
		t.Fatal(err)
	}
	did := crypto.Keccak256Hash([]byte("device-1"))
	controller := common.HexToAddress("0x1234")
	workKey := []byte("p256-work-public-key")
	vrfKey := []byte("secp256k1-vrf-public-key")

	st.SetState(TPMRegistryAddress, registrationFieldSlot(did, registrationControllerOffset), common.BytesToHash(controller.Bytes()))
	st.SetState(TPMRegistryAddress, registrationFieldSlot(did, registrationWorkKeyHashOffset), crypto.Keccak256Hash(workKey))
	st.SetState(TPMRegistryAddress, registrationFieldSlot(did, registrationVRFKeyHashOffset), crypto.Keccak256Hash(vrfKey))
	st.SetState(TPMRegistryAddress, registrationFieldSlot(did, registrationProfileHashOffset), crypto.Keccak256Hash([]byte("AMD-fTPM-3.56.0.5")))
	st.SetState(TPMRegistryAddress, registrationFieldSlot(did, registrationNullifierOffset), crypto.Keccak256Hash([]byte("EK-nullifier")))
	st.SetState(TPMRegistryAddress, registrationFieldSlot(did, registrationActiveOffset), common.BigToHash(big.NewInt(1)))

	if err := verifyTPMRegistration(st, did, controller, workKey, vrfKey); err != nil {
		t.Fatalf("valid TPM registration rejected: %v", err)
	}
	if err := verifyTPMRegistration(st, did, controller, []byte("other-work-key"), vrfKey); err == nil {
		t.Fatal("mismatched TPM work key accepted")
	}
	if err := verifyTPMRegistration(st, did, common.HexToAddress("0x5678"), workKey, vrfKey); err == nil {
		t.Fatal("mismatched controller accepted")
	}
}

func TestRegistrationSlotsAreSeparated(t *testing.T) {
	didA := crypto.Keccak256Hash([]byte("A"))
	didB := crypto.Keccak256Hash([]byte("B"))
	seen := make(map[common.Hash]bool)
	for _, did := range []common.Hash{didA, didB} {
		for offset := uint64(0); offset <= registrationActiveOffset; offset++ {
			slot := registrationFieldSlot(did, offset)
			if seen[slot] {
				t.Fatalf("storage slot collision for %s offset %d", did.Hex(), offset)
			}
			seen[slot] = true
		}
	}
}

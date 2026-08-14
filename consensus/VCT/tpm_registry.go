//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vct

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/core/state"
	"github.com/cryptoecc/WorldLand/crypto"
)

// TPMRegistryAddress is the reserved predeploy address for the TPM DID registry.
// The prototype contract source lives in contracts/tpmregistry/contract.
var TPMRegistryAddress = common.HexToAddress("0x0000000000000000000000000000000000000801")

const (
	registrySlotRegistrations     uint64 = 0
	registrationControllerOffset         = 0
	registrationWorkKeyHashOffset        = 1
	registrationVRFKeyHashOffset         = 2
	registrationProfileHashOffset        = 3
	registrationNullifierOffset          = 4
	registrationActiveOffset             = 5
)

type tpmRegistration struct {
	Controller  common.Address
	WorkKeyHash common.Hash
	VRFKeyHash  common.Hash
	ProfileHash common.Hash
	Nullifier   common.Hash
	Active      bool
}

// registrationBaseSlot follows Solidity's mapping(bytes32 => Registration)
// storage rule for a mapping declared at slot zero.
func registrationBaseSlot(did common.Hash) common.Hash {
	var mappingSlot common.Hash
	mappingSlot[31] = byte(registrySlotRegistrations)
	return crypto.Keccak256Hash(did[:], mappingSlot[:])
}

func registrationFieldSlot(did common.Hash, offset uint64) common.Hash {
	base := new(big.Int).SetBytes(registrationBaseSlot(did).Bytes())
	base.Add(base, new(big.Int).SetUint64(offset))
	return common.BigToHash(base)
}

func readTPMRegistration(st *state.StateDB, did common.Hash) (tpmRegistration, error) {
	if st == nil {
		return tpmRegistration{}, errors.New("VCT: parent state required for TPM registration")
	}
	controllerWord := st.GetState(TPMRegistryAddress, registrationFieldSlot(did, registrationControllerOffset))
	activeWord := st.GetState(TPMRegistryAddress, registrationFieldSlot(did, registrationActiveOffset))
	reg := tpmRegistration{
		Controller:  common.BytesToAddress(controllerWord.Bytes()[12:]),
		WorkKeyHash: st.GetState(TPMRegistryAddress, registrationFieldSlot(did, registrationWorkKeyHashOffset)),
		VRFKeyHash:  st.GetState(TPMRegistryAddress, registrationFieldSlot(did, registrationVRFKeyHashOffset)),
		ProfileHash: st.GetState(TPMRegistryAddress, registrationFieldSlot(did, registrationProfileHashOffset)),
		Nullifier:   st.GetState(TPMRegistryAddress, registrationFieldSlot(did, registrationNullifierOffset)),
		Active:      activeWord != (common.Hash{}),
	}
	return reg, nil
}

func verifyTPMRegistration(st *state.StateDB, did common.Hash, controller common.Address, workPublicKey, vrfPublicKey []byte) error {
	if did == (common.Hash{}) {
		return errors.New("VCT: TPM DID is zero")
	}
	reg, err := readTPMRegistration(st, did)
	if err != nil {
		return err
	}
	if !reg.Active {
		return fmt.Errorf("VCT: TPM DID %s is not active", did.Hex())
	}
	if reg.Controller != controller {
		return fmt.Errorf("VCT: TPM DID controller %s != coinbase %s", reg.Controller.Hex(), controller.Hex())
	}
	if want := crypto.Keccak256Hash(workPublicKey); reg.WorkKeyHash != want {
		return errors.New("VCT: TPM work public key does not match registry")
	}
	if want := crypto.Keccak256Hash(vrfPublicKey); reg.VRFKeyHash != want {
		return errors.New("VCT: VRF public key does not match TPM DID registry")
	}
	return nil
}

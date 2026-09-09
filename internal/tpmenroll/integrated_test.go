package tpmenroll

import (
	"context"
	"testing"

	"github.com/cryptoecc/WorldLand/accounts/abi/bind"
	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
)

type resumeFixture struct {
	lifecycleFixture
	state tpmregistry.RegistrationState
}

func (f *resumeFixture) Registration(context.Context, common.Hash) (tpmregistry.RegistrationState, error) {
	state := f.state
	state.Active = f.active
	return state, nil
}

func TestResumeIntegratedRegistration(t *testing.T) {
	controller := common.HexToAddress("0x1234")
	enrollment := tpmregistry.EnrollmentData{DID: common.HexToHash("0x1"), WorkKeyHash: common.HexToHash("0x2"), VRFKeyHash: common.HexToHash("0x3"), ProfileHash: common.HexToHash("0x4"), DeviceNullifier: common.HexToHash("0x5")}
	for _, name := range []string{"active", "activate", "wrong-controller", "wrong-work-key", "wrong-vrf", "wrong-profile", "wrong-nullifier"} {
		t.Run(name, func(t *testing.T) {
			f := &resumeFixture{state: tpmregistry.RegistrationState{Controller: controller, WorkKeyHash: enrollment.WorkKeyHash, VRFKeyHash: enrollment.VRFKeyHash, ProfileHash: enrollment.ProfileHash, DeviceNullifier: enrollment.DeviceNullifier}}
			f.active = name != "activate"
			switch name {
			case "wrong-controller":
				f.state.Controller = common.Address{}
				f.state.Controller[0] = 1
			case "wrong-work-key":
				f.state.WorkKeyHash = common.Hash{}
			case "wrong-vrf":
				f.state.VRFKeyHash = common.Hash{}
			case "wrong-profile":
				f.state.ProfileHash = common.Hash{}
			case "wrong-nullifier":
				f.state.DeviceNullifier = common.Hash{}
			}
			done, err := resumeProducer(context.Background(), commandConfig{waitActivation: true}, f, f, &bind.TransactOpts{From: controller}, nil, nil, enrollment)
			if name == "active" || name == "activate" {
				if err != nil || !done {
					t.Fatalf("resume = %v, %v", done, err)
				}
				want := 0
				if name == "activate" {
					want = 1
				}
				if f.activateCalls != want {
					t.Fatalf("activation calls = %d, want %d", f.activateCalls, want)
				}
			} else if err == nil || done || f.activateCalls != 0 {
				t.Fatalf("accepted mismatched registration: done=%v err=%v", done, err)
			}
		})
	}
}

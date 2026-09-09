package tpmenroll

import (
	"context"
	"errors"
	"math/big"
	"time"

	ethereum "github.com/cryptoecc/WorldLand"
	"github.com/cryptoecc/WorldLand/accounts/abi/bind"
	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/contracts/tpmregistry"
	"github.com/cryptoecc/WorldLand/crypto/tpmwork"
	"github.com/cryptoecc/WorldLand/ethclient"
)

type Config struct {
	ControllerKey   string
	WorkKey         string
	AttestationKey  string
	VRFPublicKey    string
	Profile         string
	EKIntermediates []string
	Identity        common.Hash
	CreateKeys      bool
	Timeout         time.Duration
}

// RunIntegrated uses only the client's in-process backend. It returns only after
// activation; it never starts mining itself. The owning lifecycle decides that.
func RunIntegrated(ctx context.Context, backend *ethclient.Client, chainID *big.Int, registry common.Address, cfg Config) error {
	if backend == nil || chainID == nil || chainID.Sign() <= 0 || cfg.Identity == (common.Hash{}) {
		return errors.New("tpmenroll: invalid integrated identity/backend")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	return runWithClient(ctx, commandConfig{action: "register-producer", registry: registry, chainID: new(big.Int).Set(chainID), controllerKey: cfg.ControllerKey, workKeyName: cfg.WorkKey, attestationKeyName: cfg.AttestationKey, createKeys: cfg.CreateKeys, vrfPublicKeyFile: cfg.VRFPublicKey, profileFile: cfg.Profile, intermediates: cfg.EKIntermediates, ekHandle: uint64(tpmwork.DefaultRSAEKHandle), ekCertificateIndex: uint64(tpmwork.DefaultRSAEKCertificateIndex), identity: cfg.Identity, waitActivation: true, resume: true}, backend)
}

type resumptionRegistry interface {
	activationRegistry
	producerEnrollmentRegistry
}

func resumeProducer(ctx context.Context, cfg commandConfig, backend enrollmentBackend, registry resumptionRegistry, auth *bind.TransactOpts, activator tpmwork.CredentialActivator, certifier tpmwork.KeyCertifier, enrollment tpmregistry.EnrollmentData) (bool, error) {
	state, err := registry.Registration(ctx, enrollment.DID)
	if err != nil {
		return false, err
	}
	if state.Controller != (common.Address{}) {
		if state.Controller != auth.From || state.WorkKeyHash != enrollment.WorkKeyHash || state.VRFKeyHash != enrollment.VRFKeyHash || state.ProfileHash != enrollment.ProfileHash || state.DeviceNullifier != enrollment.DeviceNullifier {
			return false, errors.New("tpmenroll: existing registration differs from local identity")
		}
		if state.Active {
			return true, nil
		}
		return true, finishActivation(ctx, cfg, backend, registry, auth, enrollment.DID)
	}
	head, err := backend.BlockNumber(ctx)
	if err != nil {
		return false, err
	}
	from := uint64(0)
	if head > 512 {
		from = head - 512
	}
	entries, err := backend.FilterLogs(ctx, ethereum.FilterQuery{FromBlock: new(big.Int).SetUint64(from), ToBlock: new(big.Int).SetUint64(head), Addresses: []common.Address{cfg.registry}, Topics: [][]common.Hash{{tpmregistry.ProducerEventTopic("ProducerRegistrationRequested")}, nil, {enrollment.DID}, {common.BytesToHash(auth.From.Bytes())}}})
	if err != nil {
		return false, err
	}
	for i := len(entries) - 1; i >= 0; i-- {
		event, err := tpmregistry.ParseProducerRegistrationEvent(entries[i])
		if err != nil || event.Removed || event.ResponseDeadline < head {
			continue
		}
		evidence, err := tpmregistry.DecodeEvidence(event.EvidenceBundle)
		if err != nil {
			continue
		}
		hash, err := evidence.Hash()
		if err != nil || hash != enrollment.EvidenceHash {
			continue
		}
		request, err := registry.ProducerRequest(ctx, event.RequestID)
		if err != nil {
			return false, err
		}
		if request.Threshold == 0 {
			continue
		}
		if err = completeProducerRegistration(ctx, cfg, backend, registry, auth, activator, certifier, event.RequestID, enrollment, request); err != nil {
			return true, err
		}
		return true, finishActivation(ctx, cfg, backend, registry, auth, enrollment.DID)
	}
	return false, nil
}

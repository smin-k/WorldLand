//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vct

import (
	"fmt"
	"math"
	"math/big"

	"github.com/cryptoecc/WorldLand/consensus"
	"github.com/cryptoecc/WorldLand/core/types"
)

// PrepareBlockTemplate fixes every execution- and seal-hash-sensitive field
// BEFORE transactions run. A timeout selects a later template timestamp; Seal
// waits for that timestamp without changing the already executed template.
func (ecc *ECC) PrepareBlockTemplate(chain consensus.ChainHeaderReader, header *types.Header) error {
	if chain == nil || chain.Config() == nil || header == nil || header.Number == nil {
		return fmt.Errorf("VCT: missing mining template or chain context")
	}
	if err := ecc.bindChainContext(chain); err != nil {
		return err
	}
	if ecc.shared != nil {
		return ecc.shared.PrepareBlockTemplate(chain, header)
	}
	if ecc.config.PowMode == ModeFake || ecc.config.PowMode == ModeFullFake || !chain.Config().IsVCT(header.Number) {
		return nil
	}
	if header.Number.Sign() <= 0 || header.Time > math.MaxInt64 {
		return fmt.Errorf("VCT: invalid mining template height or timestamp")
	}
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil || header.Time <= parent.Time {
		return fmt.Errorf("VCT: mining template requires its parent and a later timestamp")
	}
	if err := ecc.EnsureVRFKeys(header.Coinbase); err != nil {
		return err
	}
	weight := new(big.Int).Set(big1)
	if chain.Config().IsTPMGated(header.Number) {
		did, signer, err := ecc.ensureTPMWorkSigner()
		if err != nil {
			return err
		}
		header.TPMDID = append([]byte(nil), did[:]...)
		header.TPMWorkPublicKey = signer.PublicKey()
		header.VRFSignature = nil
	} else if cfg := chain.Config().Vct; cfg != nil {
		if b0 := cfg.MinEligibleBalanceAt(header.Number); b0.Sign() > 0 {
			backend, ok := chain.(stateBackend)
			if !ok {
				return fmt.Errorf("VCT: parent-state backend required for mining template")
			}
			st, err := backend.StateAt(parent.Root)
			if err != nil {
				return err
			}
			weight.Div(st.GetBalance(header.Coinbase), b0)
			if weight.Sign() == 0 {
				return fmt.Errorf("VCT: coinbase balance grants zero virtual trials")
			}
		}
	}
	_, proof, err := ecc.IsEligibleForBlock(chain, header.Number.Uint64(), header.ParentHash, ecc.CalcEligibilityThreshold(chain, header.Time, parent))
	if err != nil {
		return err
	}
	output, err := VRFOutputFromProof(proof)
	if err != nil {
		return err
	}
	header.VRFProof = proof
	ecc.lock.Lock()
	header.VRFPublicKey = append([]byte(nil), ecc.vrfPubKey...)
	ecc.lock.Unlock()
	// At most the configured full timeout window is searched. Recompute the
	// adaptive base at each candidate time, exactly as a receiver does.
	for {
		header.EligibilityThreshold = ecc.CalcEligibilityThreshold(chain, header.Time, parent)
		if EligibilityPassesWithWeight(output, header.EligibilityThreshold, EffectiveDeltaT(header.Time-parent.Time), weight) {
			break
		}
		if header.Time == math.MaxInt64 {
			return fmt.Errorf("VCT: mining timestamp overflow")
		}
		header.Time++
	}
	header.Difficulty = ecc.CalcDifficulty(chain, header.Time, parent)
	return nil
}

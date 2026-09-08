package vct

import (
	"fmt"

	"github.com/cryptoecc/WorldLand/consensus"
	"github.com/cryptoecc/WorldLand/core/types"
)

// vrfSeedHeader resolves the branch-local delayed ancestor used by block h.
// With delay d, the seed is the block at height max(0, h-d). Traversing from
// the candidate's parent is important: a canonical-height lookup would bind
// side-chain verification to the wrong branch.
func vrfSeedHeader(chain consensus.ChainHeaderReader, parent *types.Header, blockNumber uint64) (*types.Header, error) {
	if chain == nil || parent == nil {
		return nil, fmt.Errorf("VCT: chain and parent are required to resolve VRF seed")
	}
	delay := chain.Config().Vct.EffectiveSeedDelay()
	var target uint64
	if blockNumber > delay {
		target = blockNumber - delay
	}
	if parent.Number == nil || parent.Number.Uint64()+1 != blockNumber {
		return nil, fmt.Errorf("VCT: parent height does not precede block %d", blockNumber)
	}
	seed := parent
	for seed.Number.Uint64() > target {
		seed = chain.GetHeader(seed.ParentHash, seed.Number.Uint64()-1)
		if seed == nil {
			return nil, fmt.Errorf("VCT: delayed VRF seed ancestor at height %d unavailable", target)
		}
	}
	if seed.Number.Uint64() != target {
		return nil, fmt.Errorf("VCT: delayed VRF seed has height %d, want %d", seed.Number.Uint64(), target)
	}
	return seed, nil
}

func (ecc *ECC) delayedVRFMessage(chain consensus.ChainHeaderReader, parent *types.Header, blockNumber uint64) ([]byte, error) {
	if err := ecc.bindChainContext(chain); err != nil {
		return nil, err
	}
	seed, err := vrfSeedHeader(chain, parent, blockNumber)
	if err != nil {
		return nil, err
	}
	seedMaterial := seed.Hash().Bytes()
	// Once VCT headers are available, use their unique verified VRF output
	// instead of the malleable block hash. Multiple block templates produced by
	// the same registered VRF key at the same height then induce one future
	// lottery input. Pre-VCT/bootstrap ancestors retain the hash fallback.
	if chain.Config().IsVCT(seed.Number) && len(seed.VRFProof) > 0 {
		output, outputErr := VRFOutputFromProof(seed.VRFProof)
		if outputErr != nil {
			return nil, fmt.Errorf("VCT: delayed seed VRF output unavailable: %w", outputErr)
		}
		seedMaterial = output[:]
	}
	return computeVRFMsg(ecc.chainIDBytes(), seedMaterial, blockNumber), nil
}

// verifiedVRFOutput verifies against chain context during consensus. The
// chain-less remote-sealer path only prechecks nonce work for a locally
// prepared header; full import always repeats verification with chain context.
func (ecc *ECC) verifiedVRFOutput(chain consensus.ChainHeaderReader, header *types.Header) ([32]byte, error) {
	if chain == nil {
		return VRFOutputFromProof(header.VRFProof)
	}
	if header.Number == nil || header.Number.Sign() == 0 {
		return [32]byte{}, fmt.Errorf("VCT: VRF proof is not valid for genesis")
	}
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return [32]byte{}, fmt.Errorf("VCT: parent header unavailable for block %d", header.Number.Uint64())
	}
	msg, err := ecc.delayedVRFMessage(chain, parent, header.Number.Uint64())
	if err != nil {
		return [32]byte{}, err
	}
	return VRFVerify(header.VRFPublicKey, header.VRFProof, msg)
}

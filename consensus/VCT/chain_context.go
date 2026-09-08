package vct

import (
	"fmt"
	"math/big"

	"github.com/cryptoecc/WorldLand/consensus"
)

// bindChainContext establishes the domain before any VRF or seal-hash work.
// A validator need not have prepared a mining template before receiving its
// first header. Copy the ID rather than retaining a mutable config pointer,
// and reject reuse of this stateful engine (including a shared engine) across
// chains instead of changing the domain underneath concurrent verification.
func (ecc *ECC) bindChainContext(chain consensus.ChainHeaderReader) error {
	if chain == nil || chain.Config() == nil {
		return fmt.Errorf("VCT: chain configuration required for consensus domain")
	}
	chainID := chain.Config().ChainID
	if chainID == nil {
		chainID = new(big.Int) // Preserve the historical zero domain for nil IDs.
	}
	if chainID.Sign() < 0 || chainID.BitLen() > 256 {
		return fmt.Errorf("VCT: chain ID must fit an unsigned 256-bit consensus domain")
	}
	if ecc.shared != nil {
		if err := ecc.shared.bindChainContext(chain); err != nil {
			return err
		}
	}
	ecc.lock.Lock()
	defer ecc.lock.Unlock()
	if ecc.chainID == nil {
		ecc.chainID = new(big.Int).Set(chainID)
		return nil
	}
	if ecc.chainID.Cmp(chainID) != 0 {
		return fmt.Errorf("VCT: consensus engine bound to chain %s cannot use chain %s", ecc.chainID, chainID)
	}
	return nil
}

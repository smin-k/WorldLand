package types

import (
	"encoding/json"
	"errors"
	"math/big"

	"github.com/cryptoecc/WorldLand/common/hexutil"
)

// eligibilityThresholdJSON encodes the inclusive range [0, 2^256]. The upper
// endpoint means every uint256 VRF output is eligible. Other header quantities
// retain hexutil.Big's uint256 limit. This changes JSON decoding, not RLP/hash
// encoding or the consensus eligibility rules.
type eligibilityThresholdJSON big.Int

const allEligibleHex = "0x10000000000000000000000000000000000000000000000000000000000000000"

func (v eligibilityThresholdJSON) MarshalText() ([]byte, error) {
	n := (*big.Int)(&v)
	if n.Sign() < 0 || n.Cmp(new(big.Int).Lsh(big.NewInt(1), 256)) > 0 {
		return nil, errors.New("eligibility threshold outside [0, 2^256]")
	}
	return []byte(hexutil.EncodeBig(n)), nil
}

func (v *eligibilityThresholdJSON) UnmarshalJSON(input []byte) error {
	var text string
	if err := json.Unmarshal(input, &text); err != nil {
		return err
	}
	if text == allEligibleHex || text == "0X"+allEligibleHex[2:] {
		(*big.Int)(v).Lsh(big.NewInt(1), 256)
		return nil
	}
	var ordinary hexutil.Big
	if err := ordinary.UnmarshalText([]byte(text)); err != nil {
		return err
	}
	(*big.Int)(v).Set(ordinary.ToInt())
	return nil
}

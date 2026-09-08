package params

import (
	"math/big"
	"testing"
)

func TestVCTResearchDifficultyValidation(t *testing.T) {
	for _, d := range []uint64{0, 1024, 4096, 65536} {
		c := &ChainConfig{Vct: &VctConfig{MinimumDifficulty: d}}
		if err := c.CheckConfigForkOrder(); err != nil {
			t.Fatalf("%d: %v", d, err)
		}
	}
	for _, d := range []uint64{1, 1023} {
		c := &ChainConfig{Vct: &VctConfig{MinimumDifficulty: d}}
		if c.CheckConfigForkOrder() == nil {
			t.Fatalf("accepted %d", d)
		}
	}
	a := &ChainConfig{ChainID: big.NewInt(103993), VCTBlock: big.NewInt(1), Vct: &VctConfig{}}
	b := *a
	b.Vct = &VctConfig{MinimumDifficulty: 4096}
	if a.CheckCompatible(&b, 10) == nil {
		t.Fatal("accepted live difficulty change")
	}
}

// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package eccpow

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/core/types"
	"github.com/cryptoecc/WorldLand/params"
)

type difficultyTestChain struct {
	config *params.ChainConfig
}

func (c *difficultyTestChain) Config() *params.ChainConfig                 { return c.config }
func (c *difficultyTestChain) CurrentHeader() *types.Header                { return nil }
func (c *difficultyTestChain) GetHeader(common.Hash, uint64) *types.Header { return nil }
func (c *difficultyTestChain) GetHeaderByNumber(uint64) *types.Header      { return nil }
func (c *difficultyTestChain) GetHeaderByHash(common.Hash) *types.Header   { return nil }
func (c *difficultyTestChain) GetTd(common.Hash, uint64) *big.Int          { return nil }

func TestCalcDifficulty(t *testing.T) {
	parent := &types.Header{
		Number:     big.NewInt(7),
		Time:       1_000,
		Difficulty: new(big.Int).Set(MinimumDifficulty),
	}
	timestamp := parent.Time + uint64(BlockGenerationTime.Int64())
	chain := &difficultyTestChain{config: &params.ChainConfig{}}
	ecc := &ECC{}

	got := ecc.CalcDifficulty(chain, timestamp, parent)
	want := MakeLDPCDifficultyCalculator()(timestamp, parent)
	if got.Cmp(want) != 0 {
		t.Fatalf("frontier ECCPoW difficulty = %v, want %v", got, want)
	}
}

func TestDecodingVerification(t *testing.T) {
	ecc := ECC{}
	header := &types.Header{
		Difficulty: ProbToDifficulty(Table[0].miningProb),
		Nonce:      types.EncodeNonce(1_751_289),
		MixDigest:  common.HexToHash("0xe19d1062281167c03d5ebbcaf4bf3c803449c111b2af73d8c2c395b01645597f"),
	}

	valid, _, _, digest := VerifyOptimizedDecoding(header, ecc.SealHash(header).Bytes())
	if !valid {
		t.Fatal("known valid legacy ECCPoW decoding was rejected")
	}
	decodedDigest := common.BytesToHash(digest)
	if !bytes.Equal(header.MixDigest[:], decodedDigest[:]) {
		t.Fatalf("decoded digest = %x, want %x", decodedDigest[:], header.MixDigest[:])
	}
}

package vct

import (
	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/consensus"
	"github.com/cryptoecc/WorldLand/core/types"
)

type batchHeader struct {
	header *types.Header
	index  int
}

// batchHeaderReader resolves ancestors from the earlier part of an incoming
// batch before consulting the stored chain. Header verification is deliberately
// read-only: the batch must not have to be imported to verify its own ancestry.
// Hash and height are both checked, so a canonical header on a different branch
// cannot replace the candidate's delayed seed ancestor.
//
// As with the parallel parent check, earlier headers are provisional until all
// preceding ordered results succeed. Callers must stop importing at the first
// error; this view does not turn an unchecked batch header into stored state.
type batchHeaderReader struct {
	consensus.ChainHeaderReader
	headers map[common.Hash]batchHeader
	limit   int
}

func batchHeaderIndex(headers []*types.Header) map[common.Hash]batchHeader {
	index := make(map[common.Hash]batchHeader, len(headers))
	for i, header := range headers {
		hash := header.Hash()
		if _, exists := index[hash]; !exists {
			index[hash] = batchHeader{header: header, index: i}
		}
	}
	return index
}

func (r *batchHeaderReader) GetHeader(hash common.Hash, number uint64) *types.Header {
	if item, exists := r.headers[hash]; exists && item.index < r.limit {
		if item.header.Number != nil && item.header.Number.Uint64() == number {
			return item.header
		}
		return nil
	}
	return r.ChainHeaderReader.GetHeader(hash, number)
}

func (r *batchHeaderReader) GetHeaderByHash(hash common.Hash) *types.Header {
	if item, exists := r.headers[hash]; exists && item.index < r.limit {
		return item.header
	}
	return r.ChainHeaderReader.GetHeaderByHash(hash)
}

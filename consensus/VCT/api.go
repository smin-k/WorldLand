//go:build !gofuzz && cgo
// +build !gofuzz,cgo

package vct

import (
	"errors"

	"github.com/cryptoecc/WorldLand/common"
	"github.com/cryptoecc/WorldLand/common/hexutil"
	"github.com/cryptoecc/WorldLand/core/types"
)

var errVCTStopped = errors.New("vct engine stopped")

// API exposes VCT mining RPC methods.
type API struct {
	ecc *ECC
}

// GetWork returns a work package for external miners.
func (api *API) GetWork() ([4]string, error) {
	var (
		workCh = make(chan [4]string, 1)
		errc   = make(chan error, 1)
	)
	select {
	case api.ecc.fetchWorkCh <- &sealWork{errc: errc, res: workCh}:
	case <-api.ecc.remote.exitCh:
		return [4]string{}, errVCTStopped
	}
	select {
	case work := <-workCh:
		return work, nil
	case err := <-errc:
		return [4]string{}, err
	}
}

// SubmitWork accepts an external miner's PoW solution.
func (api *API) SubmitWork(nonce types.BlockNonce, hash, digest common.Hash) bool {
	var errc = make(chan error, 1)
	select {
	case api.ecc.submitWorkCh <- &mineResult{nonce: nonce, mixDigest: digest, hash: hash, errc: errc}:
	case <-api.ecc.remote.exitCh:
		return false
	}
	return <-errc == nil
}

// SubmitHashRate records the hash rate of a remote miner.
func (api *API) SubmitHashRate(rate hexutil.Uint64, id common.Hash) bool {
	var done = make(chan struct{}, 1)
	select {
	case api.ecc.submitRateCh <- &hashrate{done: done, rate: uint64(rate), id: id}:
	case <-api.ecc.remote.exitCh:
		return false
	}
	<-done
	return true
}

// GetHashrate returns the combined local + remote hash rate.
func (api *API) GetHashrate() uint64 {
	return uint64(api.ecc.Hashrate())
}

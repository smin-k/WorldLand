# TPM-gated VCT prototype

This branch keeps the Ethereum account key and the VRF key on secp256k1 and
adds a separate non-exportable ECDSA P-256 TPM work key. Every post-fork ECCPoW
input is derived from a fresh signature made by that work key.

## Components

- `crypto/tpmwork`: consensus signature encoding and Windows platform-KSP backend.
- `consensus/VCT`: TPM work-message construction, mining and verification.
- `contracts/tpmregistry`: fixed-collateral DID registry and parent-state layout.
- `cmd/tpmworkbench`: local TPM signing-throughput benchmark.

The registry is reserved for predeployment at
`0x0000000000000000000000000000000000000801`. Its registrar verifies EK/AK,
manufacturer evidence and work-key certification off chain. This is an
explicit trust boundary of the prototype.

## Local TPM benchmark

Creating a key is explicit and does not clear the TPM:

```powershell
go run ./cmd/tpmworkbench -key WorldLand-TPM-Work-Test -create -n 100
```

Later runs omit `-create`:

```powershell
go run ./cmd/tpmworkbench -key WorldLand-TPM-Work-Test -n 1000
```

The command prints verified signatures per second and p50/p95/p99 latency. The
persisted test key remains in the Windows platform provider; this prototype
does not delete keys.

### Initial AMD fTPM result (2026-08-14)

The development machine's AMD TPM 2.0 firmware `3.56.0.5` produced and verified
200 sequential P-256 signatures with the persisted test key:

- throughput: `72.133 signatures/s`
- p50 latency: `13.8308 ms`
- p95 latency: `14.5962 ms`
- p99 latency: `15.1082 ms`
- NCrypt private-key export policy: `0x00000000` (no export flags)
- private-blob export probe: blocked by the platform provider

This is a single-device engineering measurement, not a protocol-wide hardware
constant. Intel PTT and discrete TPM profiles must be measured separately, as
must aggregate throughput across concurrent handles and multiple keys on one
physical TPM.

## Client wiring

After the DID and key hashes are registered in the parent state, start a miner
with the corresponding key name and DID:

```text
worldland --mine --unlock <coinbase> \
  --miner.tpmkey WorldLand-TPM-Work-Test \
  --miner.tpmdid 0x<32-byte-did>
```

Add `--miner.tpmcreate` only for first-time key creation. The chain config must
schedule `tpmGatedBlock`; existing networks leave the field unset and retain
the legacy WIP-6 behavior.

## Remaining deployment work

The Solidity registry source specifies storage layout but its bytecode has not
yet been placed in a genesis allocation. Manufacturer attestation validation,
registrar governance, revocation policy and multi-vendor TPM profiles require
separate deployment decisions before a public testnet activation. The legacy
remote-sealer API also does not yet expose a TPM signing-agent protocol; the
current implementation covers local TPM-gated mining and consensus validation.

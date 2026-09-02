# TGPoW WorldLand two-node client experiment

This experiment runs the actual WorldLand client on two local nodes. The
producer executes VRF eligibility, uses the persisted non-exportable Windows
TPM P-256 work key, solves ECCPoW, and sends the resulting block through the
real devp2p/TCP path. The second node independently imports and validates it.

The checked-in account key and password are public test fixtures with no value.
Never fund this address on any public network.

The test identity is active in the private genesis. This isolates the mining,
propagation, and validation path. It does **not** replace the separate registry
contract integration and enrollment-attack tests.

On Windows with the existing `WorldLand-TPM-Work-Test` key:

```powershell
powershell -ExecutionPolicy Bypass -File experiments/tgpow-client-e2e/run-two-node.ps1
```

Each invocation creates a new timestamped directory under
`artifacts/tgpow-e2e/runs/`. It never clears a datadir or deletes a TPM key.
Both P2P listeners bind only to `127.0.0.1`, avoiding a public/private-network
firewall exception. The script stops only the two process IDs it created.

The production VCT minimum difficulty (65,536) is retained. With a platform
TPM that signs about 40 times per second, the expected wait for one block is
roughly 27 minutes and has a long geometric tail; the default timeout is 90
minutes.

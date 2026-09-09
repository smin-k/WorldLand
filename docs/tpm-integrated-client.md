# Integrated TPM enrollment (opt-in)

`worldland --tpm.integrated /path/to/integrated.json` runs producer preparation
and optional enrollment inside the client. The standalone `tpmproducer` and
`tpmenroll` commands remain compatible wrappers around the shared implementation.
Do not run them concurrently with integration for the same controller.

## Configuration

Example shape (replace paths and supply the chain's allowed profile hashes):

```json
{
  "Producer": {
    "KeyFile": "/secure/controller.key",
    "CertificateProfile": "gcp-cas-v1",
    "ProfileHashes": [],
    "Lookback": 512,
    "MaxPerSlot": 4,
    "GasLimit": 1200000
  },
  "Enrollment": {
    "AttestationKey": "WorldLand-TPM-AIK",
    "VRFPublicKey": "/secure/controller.pub",
    "Profile": "/secure/profile.json",
    "EKIntermediates": []
  },
  "Enroll": true,
  "PreparationTimeoutSeconds": 5
}
```

Use the existing network/datadir/account settings, `--mine`, `--miner.tpmkey`
and `--miner.tpmdid`. The latter must match the actual TPM-derived identity.
The producer key must match the mining coinbase. The coinbase account must also
be unlocked through the existing client account configuration for VRF mining.
Keep key files local with restrictive permissions; never publish the key file.
Enrollment uses the producer controller key and miner work-key/create settings.
TPM keys, certificate chains and profile provisioning remain prerequisites;
on GCP retain the existing `WORLDLAND_TPM_EK_CERT` configuration. The certificate
policy must match the registry policy; the example is not a universal policy.
Use `Enroll: false` for pre-registered bootstrap producers.

## Behavior and limits

* Communication uses an in-process RPC attachment, not an external RPC endpoint.
* Producer preparation runs before any sealing candidate, including empty blocks.
  It prepares parent-bound challenges and verified approvals. Execution failure,
  timeout or changed parent discards the local candidate instead of sealing it.
* Enrollment waits for activation before automatically starting mining. Restart
  recognizes a matching active registration, resumes activation, or searches the
  last 512 blocks for a matching live request. Mismatched identity data is rejected.
* Enrollment defaults to a 30-minute deadline. Failure is logged and does not
  automatically start mining or retry indefinitely; investigate and restart.
* Preparation defaults to five seconds and bounded transaction staging. This is
  not proof of denial-of-service resistance or guaranteed slot completion under
  overload. Consensus quorum, deadlines and certificate verification are unchanged.
* Enrollment still polls responses internally. Only producer preparation is
  synchronized with candidate construction. Automatic re-enrollment after a
  later reorg removes an already activated registration is not implemented.

## Validation / rollout

Subsequent status (2026-09-09): a real six-node GCP vTPM rollout and bounded
adversarial/performance campaign completed. See
[`../experiments/tgpow-gcp-full/README.md`](../experiments/tgpow-gcp-full/README.md)
for evidence and limits. The procedure below remains deployment guidance rather
than a claim that integration alone provides consensus-wide evidence validation.

Local regression tests cover shared enrollment/producer logic and the mining
barrier (no early sealing, cancellation, changed parent and preparation error).
These tests do not replace a real TPM integration run. Before rollout, preserve
the existing testnet baseline, build on Linux with CGO enabled (VCT requires it),
stop external helpers, and validate fresh enrollment and restart on a separate
test chain. No live testnet rollout is implied by enabling this code locally.

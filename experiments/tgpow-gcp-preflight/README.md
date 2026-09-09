# GCP real vTPM preflight — 2026-09-08

Scope: one disposable Confidential VM, no cryptocurrency mining or testnet.
User authorized a short EK/TPM test; provisional cost ceiling KRW 1,000.
Actual free-trial credit balance was not independently verified.

- Account: smin8030@gmail.com
- Project: project-b705fc06-c245-4131-9fb
- VM: wl-tpm-probe-20260908, ID 668659950686442718
- Zone: us-central1-b (us-central1-a failed with resource exhaustion;
  instance/disk absence checked before retry)
- Machine: n2d-standard-2, AMD Milan, Confidential SEV
- Image: Ubuntu 22.04 LTS; 20 GB balanced NVMe boot disk, auto-delete
- Dedicated VPC/subnet: wl-tpm-probe-20260908; no ingress firewall rules
- No service account, API scopes, or SSH keys attached
- Platform maximum runtime: 1,800 seconds, termination action DELETE
- Guest safety shutdown: 20 minutes after startup

The Compute Engine API was enabled for this project. Existing projects and
resources were not changed. The startup metadata contains public source code
and the public EK certificate, never private keys or account credentials.

## Findings and corrections

The authenticated GCP Shielded Identity API returned a nonempty RSA EK PEM
certificate (2,171 characters). `ek.pem` is the returned public leaf certificate.
Its subject includes this instance ID; issuer is Google EK/AK CA Intermediate.
This alone does not establish the registry's certificate trust policy.

Initial startup failed before TPM access because the startup environment had
no Go cache/home defaults. Explicit GOPATH/GOCACHE paths fixed the build.

The first actual TPM run passed five work signatures, persistent key reopen,
and TPM2_Certify. EK matching failed. Investigation against go-tpm v0.3.3's
official `examples/tpm2-ekcert` identified the missing 256-byte zero unique
field in our RSA EK CreatePrimary template. That input affects key derivation.
The backend was corrected and a regression assertion added. The initial result
is retained in `result-before-ek-template-fix.json`; validation was not bypassed.

## Corrected real-device result

`result.json` records success on the same VM after the EK template correction:

- Work signatures: 5 verified, canonical P-256 low-s format.
- Persistent key reopen: same work public key; also unchanged across the reset.
- TPM2_Certify: verified by the existing WorldLand portable verifier.
- EK certificate: 1,561-byte DER leaf matches the actual TPM-derived RSA EK.
- MakeCredential/ActivateCredential: verifier-generated random secret recovered.
- Tampered credential: rejected by the TPM.
- Mining: false. No consensus network or explorer was started.

`certificateChainTrusted` remains **false** deliberately: the probe checks EK
public-key matching and possession, not approval of a Google CA trust anchor.
The observed leaf has no Extended Key Usage extension (2.5.29.37); a registry
policy requiring the TCG EKCertificate EKU cannot accept it unchanged. Any GCP
profile must explicitly review certificate issuance, roots and usage checks;
this experiment neither weakens nor installs such a profile. End-to-end on-chain
enrollment, full Linux CGO node build and multi-node consensus remain untested.

## Cleanup

The exact VM ID and experiment label were verified before deletion. The VM and
its auto-delete boot disk were deleted; subsequent instance and disk list queries
both returned empty arrays. GCP also confirmed deletion of the dedicated subnet
and VPC `wl-tpm-probe-20260908`. Cleanup is complete; no experiment VM remains.
The disposable vTPM test keys were removed with the VM and are not recoverable;
the public certificate and result evidence are retained locally.
The project, billing account, and Compute Engine API remain available. No keys,
VM snapshots, reserved addresses, service accounts or firewall rules were created.
Actual billed amount / free-trial credit deduction has not been queried.

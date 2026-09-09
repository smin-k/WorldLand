# AWS TPM preflight — 2026-09-07

User-authorized target: five real WorldLand nodes (two genesis identities and
three post-genesis registrations), Blockscout, approximately KRW 20,000 total,
until approximately 2026-09-08 13:00 Asia/Seoul. No existing AWS service may be
modified or reused without separate authorization.

## Disposable preflight only

- AWS profile/region: `dfvrf` / `ap-northeast-2`.
- Instance: `i-0f3acb49a3f44c228`, launched 2026-09-07 14:32:25 UTC.
- Security group: `sg-059913b1d032710a1` (no inbound rules).
- Exact experiment tag: `tgpow-preflight-20260907-1435`.
- Amazon image: `ami-0f7c9915974b2db69`, TPM Windows Server 2022 base.
- `t3a.small`, Standard CPU credits, encrypted 30 GiB gp3 root, no public IP,
  no SSH/RDP access, no IAM instance profile, no account keys in user data.
- OS shutdown terminates the instance and deletes its root volume. User data
  schedules shutdown 900 seconds after it starts, before querying the TPM.
- Independently inspect and terminate this exact instance if user data fails;
  do not rely only on the guest timer. Remove its security group after shutdown.

The preflight checks TPM presence, manufacturer/enterprise EK certificate
counts, and TPM2_NV_ReadPublic at the standard RSA certificate index 0x01c00002.
It does not mine, enroll, generate a replacement EK certificate, or change the
enrollment trust policy. Only public diagnostic metadata goes to serial output.

## Gate before the five-node deployment

Current enrollment requires a manufacturer-certified RSA EK and a fixed
canonical public template. AWS API endorsement-key retrieval and Nitro signed
attestation documents are not automatically equivalent to that certificate
policy. If the preflight does not supply compatible evidence, stop expansion
and ask the user before implementing an AWS-specific trust profile.

## Result

At 2026-09-07 14:34:08 UTC the real instance reported TPM present/ready,
manufacturer AMZN, and EK present. Both manufacturer and additional certificate
counts were zero. The standard RSA EK certificate NV public query returned
`80-01-00-00-00-0A-00-00-00-8B` (TPM error), not certificate metadata.
See `result.json` for the serial-console evidence.

Current Windows `EnrollmentIdentity` requires reading the RSA EK certificate
from that NV index; `Policy.ValidateEvidence` requires a valid trusted X.509
certificate. No verification bypass or synthetic certificate was introduced.
AWS-authenticated EK pinning would require a separately specified trust profile
and implementation; it is not the existing manufacturer-certificate experiment.

Status: deployment gate failed; no five-node testnet or explorer deployed.
Cleanup verified: instance `i-0f3acb49a3f44c228` is `terminated`, no volumes
remain with the exact experiment tag, and deletion of security group
`sg-059913b1d032710a1` returned success. No public IP, IAM role, key pair,
snapshot, AMI, or explorer server was created. Existing services were untouched.

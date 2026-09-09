# GCP five-node TGPoW experiment (2026-09-08)

User reported provider permission to proceed. Target: two genesis-enrolled
nodes, three dynamically enrolled nodes, real GCP vTPMs, read-only explorer.
No simulated signer or alternate consensus is permitted.

Project: project-b705fc06-c245-4131-9fb; zone: us-central1-b.
Dedicated resource prefix: wl-tgpow-0908. VM names: wl-tgpow-0908-n1 through n5.
Initial build VM is limited to two hours with DELETE termination and an
auto-delete boot disk. Extend only after successful build/TPM checks, within
the user's approximate KRW 20,000 budget and next-day observation window.

Management SSH is IAP-only. P2P is limited to the experiment subnet. Private
miner/admin RPC must bind loopback; the explorer must expose read-only data.
No service account or API scopes are attached to the VM. Temporary SSH keys,
source archives, account keys and runtime outputs belong under ignored
artifacts/tgpow-gcp-testnet, never in the source archive or public explorer.

Status: restarted on 2026-09-08 17:37 KST with chain ID 103993 and initial/minimum
difficulty 4096. All five nodes received the same binary and genesis. Real TPM
blocks were observed; late nodes finalized enrollment around 17:40 KST.
Explorer: http://34.30.246.193:8080/ (the former IP is no longer the explorer).
All five VMs now have DELETE terminationTime 2026-09-09T03:00:00Z (12:00 KST),
with auto-delete boot disks. The old 7200-second limit was cleared on all five.
The prior chain is in /opt/worldland-testnet/archive-65536 on each VM; public-only
chain/log archives are downloaded to ignored local artifacts. Private keys stay
on their respective VMs. Heartbeat automation worldland-4096 checks every 15 min;
it depends on this PC/app remaining available, unlike GCP's automatic deletion.

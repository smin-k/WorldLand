# Actual network partition/reorg — 2026-09-08 UTC

Six real GCP vTPM clients, fresh data-reorg, three bootstrap identities and three
late registrations. Same normal measured binary as eligibility sweep. Groups
{1,4,5} and {2,3,6}; only cross-group TCP30303 dropped by a dedicated local rule.
IAP/SSH/observer remained reachable. No cloud firewall changes.

Split rules applied14:47:59–14:48:02. Independent autoheal timers were scheduled
before adding rules. They actually ran14:51:00–14:51:40 (about181–220seconds),
because default systemd timer accuracy permits delay. All6 restored INPUT/OUTPUT
to ACCEPT without experiment jumps. Future script adds AccuracySec=1s; this was
NOT retrospectively the timing of the observed run.

Late nodes started enrollment14:48:34–38 while partitioned. Both groups made
blocks and registration evidence. At height16:

- Group A: 0xabd7625c005dbf4c11093e9f838dbd7b54baa34d6049890e40c76f9b04e97bd8
- Group B: 0x918d9fb08a9fcdbc2f6f951e03778eada06536c1bc2962f8c9c6689adb43fed1

Node4 at14:51:37 reported common ancestor15, dropped10 blocks, added11. A copied
clean DB independently contains exactly the ten displaced blocks16..25. Those
include4 approval events for the node4/node5 requests (slots22 and23). None of
those4 approval transactions emits a registry event on the final canonical chain.
The same registration begins reappear on the winning chain; final node4/node5
requests instead have all6 challenges/responses/approvals at slots38..43.
Node6's winning-branch request has all6 at slots20..25. All three finalized and
all identities activated. Node4's activation log is14:54:50.945; a preceding
observer sample showed active state before its local mining flag caught up.

At height64 ALL SIX agree:

- hash 0x814b7a842e8735869567967dbbe94cd6ade8c46781be0758d18e570576991c74
- stateRoot 0x47f4c7318e1c3459c8b9d2cfb420738fb02665a18a9d3fa2499ceb89ea4329f8

All12 split/healed block snapshots have consistent adjacent parent links. This
guards against mixing branches while fetching headers by number. Verification:
`experiments/tgpow-gcp-full/assert-reorg.ps1` and read-only `fork-audit` utility.
This is one observed actual reorg with event non-reuse and recovery, not a proof
against every replay or fork strategy. An additional one-block natural reorg at
height54 was also logged and is separate from the intentional split.

Evidence under ignored artifacts/tgpow-gcp-full:
nN-reorg-split.tgz, nN-reorg-healed.tgz, nN-frozen-reorg.tgz, status-reorg-split.json.
All six clean frozen DBs downloaded and hash checked before the next phase.
Node4 frozen SHA256 f5ebbe0d3056e4960f0420f6813a09a6c208380a78fce20de378abc320f54a1a.
The fork audit reads only an extracted PUBLIC chaindata backup, never live DBs.

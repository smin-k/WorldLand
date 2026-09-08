# Isolated low-difficulty TPM experiment

VCT's default WIP-8 minimum remains 65536. Isolated research chains may set
`config.vct.minimumDifficulty` in genesis; nonzero values below 1024 are rejected
because the WIP-5 integer adjustment step would become zero. Changing this
configuration after VCT activation is rejected by configuration compatibility
checks. This is a consensus parameter, not a per-miner preference.

The five-node GCP demo uses chain ID 103993, genesis difficulty 4096 and minimum
difficulty 4096. Two identities are bootstrapped; three enroll after genesis.
Activation delay remains six blocks and the producer approval threshold remains
two. TPM signatures, credential activation and the explicit GCP EK certificate
policy are unchanged. Chain-bound DIDs are re-derived from validated evidence.

This run tests functional enrollment, synchronization and TPM-backed mining.
Its lower work requirement must not be presented as production security or
production performance evidence. Block intervals are stochastic, and changing
the difficulty floor also changes the operating range of the controller.

When repeating a run, stop clients before archiving their databases. Preserve
old chain data and logs separately, never include account/TPM private material
in public artifacts, and initialize every node with the same new genesis.

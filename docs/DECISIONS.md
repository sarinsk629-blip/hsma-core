# DECISIONS.md — HSMA Protocol Architectural Ledger
Status: INITIALIZED
Tracking: v0.7 Baseline

| ID | Component | Decision | Rationale | Supersedes |
|---|---|---|---|---|
| DEC-001 | Arithmetic (P0) | Pasta curves (Pallas/Vesta), L≈126, unsigned mag + sign flags. | Native HyperNova synergy; sidesteps disjunctive range checks. | N/A |
| DEC-002 | Sequencing (M1) | Commit-then-Simulate (Solvable Prefix) via 192-node committee. | Eliminates joint insolvency mid-fold and deterministic ordering MEV. | N/A |
| DEC-003 | Accumulator (P5) | Saturation: Clamp-with-counter via L'=127 scratchpad. | Prevents 96-bit accumulator overflow; preserves network liveness. | N/A |
| DEC-004 | Activations (P5) | Sigmoid domain ±28; 1-LSB (ε < 2^-16) rule strictly retained. | Ensures mathematical uniformity across all bounds. | N/A |
| DEC-005 | Table Eval (P5) | Degree-2 chunk interpolation (T_0, T_1, T_2). | Achieves O(h^3) error drop, satisfying 1-LSB gate without table bloat. | N/A |
| DEC-006 | Lookup Auth (P5) | Standard LogUp pipeline (Commit → γ → Sum-Check). | Resolves multilinear degree mismatch and adaptive-collision grinding. | N/A |
| DEC-007 | Rounding (P5) | RNTE strict witness constraints (q, r, b) with tie-breaker logic. | Closes prover-discretion gap at exact halfway ties. | N/A |
| DEC-008 | Integrity (P5) | arch_root, work_manifest, fidelity_report_root bound to ModelCommit. | Closes billing inflation and model-swapping vulnerability. | N/A |
| DEC-009 | Constraints (P5) | 10-bit range checks on u_low via boolean bit-decomposition. | Avoids LogUp table bloat and lookup-argument constraint inflation. | N/A |
| DEC-010 | Sybil Defense (S1) | Prioritize Validator Admission, Staking Bonds, and Weight Accounting. | Sybil resistance is governed by weight creation and capital bounds (f < 0.20). | N/A |
| DEC-011 | Circuit Hygiene (P5)| Enforce row-selector gating q · (u_low - Σ 2^i b_i) = 0. | Prevents unconstrained witness coordinates on padded rows. | DEC-009 |
| DEC-012 | Weights (S1) | Cap evaluated against uncapped total T_0 in a single pass. | Eliminates fixpoint non-determinism and dust-sybil inflation. | S1-v1 §2.1 |
| DEC-013 | Weights (S1) | Cluster-level W_max via payout-graph linkage and attestations. | Prevents neutral Sybil-splitting cap evasion (perjury-slashable). | S1-v1 §2.2 |
| DEC-014 | Weights (S1) | Φ eligibility requires burned fees ≥ floor price, paid by non-cluster. | Prevents PoUW degenerating into PoW via self-dealing. | S1-v1 §2.1 |
| DEC-015 | Numerics (S1) | W_i = ⌊(Φ_i^6 · S_i^4)^{1/10}⌉ via integer Newton root, RNTE. | Closes irrational fractional power gap for deterministic circuit folds. | S1-v1 §2.1 |
| DEC-016 | Slashing (S1/MSSC) | Canonical domain-separated vote preimage (HSM_MSSC_VOTE_v1). | Prevents honest nodes from being slashed for legitimate preference updates. | S1-v1 §4 |
| DEC-017 | Exit (S1) | Escrow extended by E_ev (14 days) past unbonding. Checkpoint sync. | Closes long-range attacks and ensures historical key accountability. | S1-v1 §5 |
| DEC-018 | Liveness (S1) | Corroborated delivery gating, exit-queue exemption, soft-to-hard ladder. | Prevents partition-hostile slashing and targeted sampler eclipsing. | S1-v1 §4 |
| DEC-019 | Numerics (S1) | Unit normalization with strict width invariant 6a + 4b + ε_guard ≤ 126. | Prevents F_p field overflow (mod p wraparound) during weight calculation. | S1-v2 §2.1 |
| DEC-020 | Weights (S1) | Intra-cluster capped weight distributed via largest-remainder rounding. | Closes arithmetic cap-evasion loophole within clusters. | S1-v2 §2.2 |
| DEC-021 | Numerics (S1) | Re-pinned RNTE (Round-to-Nearest-Ties-to-Even) strictly across all math. | Eliminates prover-discretion gap on exact halfway ties. | S1-v2 §2.1 |
| DEC-022 | Gossip (G1) | 4-Tier Message Taxonomy (P0-P3). P3 is pull-only, bounded by MAX_PROOF_BYTES. | Enforces compute-budget gating and eliminates verification-DoS. | N/A |
| DEC-023 | Incentives (G1) | Informer Reward (δ_info = 0.5% of burn) paid to first relay of P0 evidence. | Converts network censorship into an economically losing partition attack. | N/A |
| DEC-024 | Identity (G1) | contact_root added to epoch header. MSSC dials strictly by pre-commitment. | Kills last-mile Sybil endpoint injection and reputation laundering. | N/A |
| DEC-025 | Sequencing (M2) | Pipeline inverted to Commit-then-Simulate. | Resolves M1/M2 paradox. Eliminates committee front-running cartel. | M1-v1 core semantics |
| DEC-026 | Privacy (M2) | Envelope schema: {sender_pk, nonce, fee_escrow} cleartext; payload encrypted. | Preserves MSSC conflict-set routing and spam pricing while hiding content. | N/A |
| DEC-027 | Ordering (M2) | Beacon-shuffled ordering lock: Sort(H("HSM_ORDER_v1" ‖ beacon_E ‖ H(ct))). | Destroys positional MEV. Brute-forcing positions incurs direct nonce-burn costs. | N/A |
| DEC-028 | Committee (M2) | 192 active + 32 standby, joint DKG, t=128; weighted beacon sortition. | Balances confidentiality (≥ 8.7σ) against liveness faults. | N/A |
| DEC-029 | Liveness (M2) | Degradation ladder L0–L3; 100% refund on committee-fault skip. | Committee censorship becomes a pure cost center; user funds are never burned. | N/A |
| DEC-030 | Folding (P4/M2) | Unified trust anchor: decree_root certified by same t-of-n threshold BLS. | Massive prover economy; establishes single cryptographic trust root across pillars. | N/A |
| DEC-031 | Folding (P4) | Self-Send Routing: If sender == recipient, circuit asserts recipient_pre == sender_post. | Prevents state collision and balance inflation during self-transfers. | N/A |
| DEC-032 | Folding (P4) | Fee Underflow Protection: Explicit LT gate balance >= Δ_req before subtraction. | Prevents unsigned magnitude wraparound on insolvent accounts. | N/A |
| DEC-033 | Folding (P4) | PAD Routing Bypass: b_PAD skips state verification constraints entirely. | Enforces Padding-Neutrality without bloating constraint count. | N/A |
| DEC-034 | Folding (P4) | Certificate Assumption: Circuit assumes decree_root valid; verifier checks BLS out-of-circuit. | Avoids 10^6+ constraint in-circuit pairing verification. | N/A |
| DEC-035 | P2P (G1) | NetworkAdapter Interface: Consensus and Mempool interact via AccountID/ContentID. | Decouples cryptography from transport, enabling future PQ agility. | N/A |
| DEC-036 | P2P (G1) | P0 Evidence DoS Guard: P0 messages require peer score ≥ θ_gray or consume budget. | Prevents CPU exhaustion via fake slashing evidence spam. | N/A |
| DEC-037 | P2P (G1) | Grace Period Eclipse Defense: Hard /24 (max 2) and ASN caps. Dial 4 Bridge nodes. | Prevents eclipse attacks during initial sync. | N/A |
| DEC-038 | P2P (G1) | P3 Pull Redundancy: Proof requests broadcast to 3 relay paths. | Prevents selfish node sync starvation. | N/A |
| DEC-039 | Theory (A6) | Sequential Quorum Accumulation applied to MSSC safety bounds. | Isolated union bound insufficient; sequential independent sampling yields ε << 2^-128. | N/A |

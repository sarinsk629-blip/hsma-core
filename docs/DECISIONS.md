<div align="center">

# 🏛 HSMA — DECISION LEDGER
### Holographic Spin-Manifold Architecture · `docs/DECISIONS.md`

**Every claim traceable to a decision ID · every decision carries rationale and supersession chain**

*Append-only discipline (DEC-046/109) — corrections travel as errata, never as rewrites*

</div>

---

## 📊 Ledger Status

| | |
|---|---|
| **Baseline** | v1.0 Ratified · Whitepaper v1.0 (A6 Theory Debt CLOSED — all 6 obligations) |
| **Implementation** | GATE GREEN — 6/6 conformance tests (Steps 2–6 kernels) |
| **Phase** | **0 — bare-metal core, IN PROGRESS** · Phase-1 gate: `GOLDEN_PARAMS_PINNED=false` (DEC-101) |
| **Verified rows** | DEC-001 … DEC-115 (Sections I–VI) |
| **Citation-recovered** | DEC-116 … DEC-180 · CA-78 … CA-135 (Section VII) |
| **Findings register** | CA-1…CA-135 · PF-1…PF-9 · SE-1…SE-10 · PRE series · CA-R series |
| **Errata** | E-1 … E-11 |
| **Format** | ADR-style blocks · render-format v3.1 (CA-R13/R14/R15, 2026-09-04) |

---

## 📑 Contents

**I** Core Crypto (DEC-001–039) · **II** Whitepaper Audit (040–068) · **III** Network/Folding/Security (069–086) · **IV** Impl/Economics (087–097) · **V** Bare-Metal Steps 1–2 (098–106) · **VI** Poseidon/Vault/State (107–115) · **VII** Implementation-Session (116–180) · Registers: Findings · Errata · A6 · Verification · Reconciliation

---

## SECTION I — Core Cryptographic Specifications (DEC-001 to DEC-039)

### DEC-001 — Arithmetic (P0)

**Decision:** Pasta curves (Pallas/Vesta), L=126, unsigned mag + sign flags.
**Rationale:** Native HyperNova synergy; sidesteps disjunctive range checks.
**Supersedes:** —

### DEC-002 — Sequencing (M1)

**Decision:** Simulate-then-Commit (Solvable Prefix) via 192-node committee.
**Rationale:** Eliminates joint insolvency mid-fold and deterministic ordering MEV.
**Supersedes:** —

### DEC-003 — Accumulator (P5)

**Decision:** Saturation: Clamp-with-counter via L'=127 scratchpad.
**Rationale:** Prevents 96-bit accumulator overflow; preserves network liveness.
**Supersedes:** —

### DEC-004 — Activations (P5)

**Decision:** Sigmoid domain +/-28; 1-LSB (eps < 2^-16) rule strictly retained.
**Rationale:** Ensures mathematical uniformity across all bounds.
**Supersedes:** —

### DEC-005 — Table Eval (P5)

**Decision:** Degree-2 chunk interpolation (T_0, T_1, T_2).
**Rationale:** Achieves O(h^3) error drop, satisfying 1-LSB gate without table bloat.
**Supersedes:** —

### DEC-006 — Lookup Auth (P5)

**Decision:** Standard LogUp pipeline (Commit -> gamma -> Sum-Check).
**Rationale:** Resolves multilinear degree mismatch and adaptive-collision grinding.
**Supersedes:** —

### DEC-007 — Rounding (P5)

**Decision:** RNTE strict witness constraints (q, r, b) with tie-breaker logic.
**Rationale:** Closes prover-discretion gap at exact halfway ties.
**Supersedes:** —

### DEC-008 — Integrity (P5)

**Decision:** arch_root, work_manifest, fidelity_report_root bound to ModelCommit.
**Rationale:** Closes billing inflation and model-swapping vulnerability.
**Supersedes:** —

### DEC-009 — Constraints (P5)

**Decision:** 10-bit range checks on u_low via boolean bit-decomposition.
**Rationale:** Avoids LogUp table bloat and lookup-argument constraint inflation.
**Supersedes:** —

### DEC-010 — Sybil Defense (S1)

**Decision:** Prioritize Validator Admission, Staking Bonds, and Weight Accounting.
**Rationale:** Sybil resistance is governed by weight creation and capital bounds (f < 0.20).
**Supersedes:** —

### DEC-011 — Circuit Hygiene (P5)

**Decision:** Enforce row-selector gating q * (u_low - sum 2^i b_i) = 0.
**Rationale:** Prevents unconstrained witness coordinates on padded rows.
**Supersedes:** DEC-009

### DEC-012 — Weights (S1)

**Decision:** Cap evaluated against uncapped total T_0 in a single pass.
**Rationale:** Eliminates fixpoint non-determinism and dust-sybil inflation.
**Supersedes:** S1-v1 Sec 2.1

### DEC-013 — Weights (S1)

**Decision:** Cluster-level W_max via payout-graph linkage and attestations.
**Rationale:** Prevents neutral Sybil-splitting cap evasion (perjury-slashable).
**Supersedes:** S1-v1 Sec 2.2

### DEC-014 — Weights (S1)

**Decision:** Phi eligibility requires burned fees >= floor price, paid by non-cluster.
**Rationale:** Prevents PoUW degenerating into PoW via self-dealing.
**Supersedes:** S1-v1 Sec 2.1

### DEC-015 — Numerics (S1)

**Decision:** W_i = floor((Phi_i^6 * S_i^4)^(1/10)) via integer Newton root, RNTE.
**Rationale:** Closes irrational fractional power gap for deterministic circuit folds.
**Supersedes:** S1-v1 Sec 2.1

### DEC-016 — Slashing (S1/MSSC)

**Decision:** Canonical domain-separated vote preimage (HSM_MSSC_VOTE_v1).
**Rationale:** Prevents honest nodes from being slashed for legitimate preference updates.
**Supersedes:** S1-v1 Sec 4

### DEC-017 — Exit (S1)

**Decision:** Escrow extended by E_ev (14 days) past unbonding. Checkpoint sync.
**Rationale:** Closes long-range attacks and ensures historical key accountability.
**Supersedes:** S1-v1 Sec 5

### DEC-018 — Liveness (S1)

**Decision:** Corroborated delivery gating, exit-queue exemption, soft-to-hard ladder.
**Rationale:** Prevents partition-hostile slashing and targeted sampler eclipsing.
**Supersedes:** S1-v1 Sec 4

### DEC-019 — Numerics (S1)

**Decision:** Unit normalization with strict width invariant 6a + 4b + eps_guard <= 126.
**Rationale:** Prevents F_p field overflow (mod p wraparound) during weight calculation.
**Supersedes:** S1-v2 Sec 2.1

### DEC-020 — Weights (S1)

**Decision:** Intra-cluster capped weight distributed via largest-remainder rounding.
**Rationale:** Closes arithmetic cap-evasion loophole within clusters.
**Supersedes:** S1-v2 Sec 2.2

### DEC-021 — Numerics (S1)

**Decision:** Re-pinned RNTE (Round-to-Nearest-Ties-to-Even) strictly across all math.
**Rationale:** Eliminates prover-discretion gap on exact halfway ties.
**Supersedes:** S1-v2 Sec 2.1

### DEC-022 — Gossip (G1)

**Decision:** 4-Tier Message Taxonomy (P0-P3). P3 is pull-only, bounded by MAX_PROOF_BYTES.
**Rationale:** Enforces compute-budget gating and eliminates verification-DoS.
**Supersedes:** —

### DEC-023 — Incentives (G1)

**Decision:** Informer Reward (delta_info = 0.5% of burn, cap 1000) paid to first relay of P0 evidence.
**Rationale:** Converts network censorship into an economically losing partition attack.
**Supersedes:** —

### DEC-024 — Identity (G1)

**Decision:** contact_root added to epoch header. MSSC dials strictly by pre-commitment.
**Rationale:** Kills last-mile Sybil endpoint injection and reputation laundering.
**Supersedes:** —

### DEC-025 — Sequencing (M2)

**Decision:** Pipeline inverted to Commit-then-Simulate.
**Rationale:** Resolves M1/M2 paradox. Eliminates committee front-running cartel.
**Supersedes:** M1-v1 core semantics (DEC-002)

### DEC-026 — Privacy (M2)

**Decision:** Envelope schema: {sender_pk, nonce, fee_escrow} cleartext; payload encrypted.
**Rationale:** Preserves MSSC conflict-set routing and spam pricing while hiding content.
**Supersedes:** —

### DEC-027 — Ordering (M2)

**Decision:** Beacon-shuffled ordering lock: Sort(H("HSM_ORDER_v1"
**Rationale:**
**Supersedes:** beacon_E

### DEC-028 — Committee (M2)

**Decision:** 192 active + 32 standby, joint DKG, t=128; weighted beacon sortition; <=16 seats/cluster.
**Rationale:** Balances confidentiality (>= 8.7 sigma) against liveness faults.
**Supersedes:** —

### DEC-029 — Liveness (M2)

**Decision:** Degradation ladder L0-L3; 100% refund on committee-fault skip.
**Rationale:** Committee censorship becomes a pure cost center; user funds are never burned.
**Supersedes:** —

### DEC-030 — Folding (P4/M2)

**Decision:** Unified trust anchor: decree_root certified by same t-of-n threshold BLS.
**Rationale:** Massive prover economy; establishes single cryptographic trust root across pillars.
**Supersedes:** —

### DEC-031 — Folding (P4)

**Decision:** Self-Send Routing: If sender == recipient, circuit asserts recipient_pre == sender_post.
**Rationale:** Prevents state collision and balance inflation during self-transfers.
**Supersedes:** —

### DEC-032 — Folding (P4)

**Decision:** Fee Underflow Protection: Explicit LT gate balance >= delta_req before subtraction.
**Rationale:** Prevents unsigned magnitude wraparound on insolvent accounts.
**Supersedes:** —

### DEC-033 — Folding (P4)

**Decision:** PAD Routing Bypass: b_PAD skips state verification constraints entirely.
**Rationale:** Enforces Padding-Neutrality without bloating constraint count.
**Supersedes:** —

### DEC-034 — Folding (P4)

**Decision:** Certificate Assumption: Circuit assumes decree_root valid; verifier checks BLS out-of-circuit.
**Rationale:** Avoids 10^6+ constraint in-circuit pairing verification.
**Supersedes:** —

### DEC-035 — P2P (G1)

**Decision:** NetworkAdapter Interface: Consensus and Mempool interact via AccountID/ContentID.
**Rationale:** Decouples cryptography from transport, enabling future PQ agility.
**Supersedes:** —

### DEC-036 — P2P (G1)

**Decision:** P0 Evidence DoS Guard: P0 messages require peer score >= theta_gray or consume budget.
**Rationale:** Prevents CPU exhaustion via fake slashing evidence spam.
**Supersedes:** —

### DEC-037 — P2P (G1)

**Decision:** Grace Period Eclipse Defense: Hard /24 (max 2) and ASN caps. Dial 4 Bridge nodes.
**Rationale:** Prevents eclipse attacks during initial sync.
**Supersedes:** —

### DEC-038 — P2P (G1)

**Decision:** P3 Pull Redundancy: Proof requests broadcast to 3 relay paths.
**Rationale:** Prevents selfish node sync starvation.
**Supersedes:** —

### DEC-039 — Theory (A6)

**Decision:** Sequential Quorum Accumulation applied to MSSC safety bounds.
**Rationale:** Isolated union bound insufficient; sequential independent sampling yields eps << 2^-128.
**Supersedes:** —

---

## SECTION II — Whitepaper Deep Audit Decisions (DEC-040 to DEC-068)

### DEC-040 — Crypto

**Decision:** BLS12-377 threshold-BLS anchor certified by same t-of-n across pillars.
**Rationale:** Unified asymmetric trust anchor across beacon, manifest, and checkpoints.
**Supersedes:** —

### DEC-041 — Theory (A6)

**Decision:** Equivocation detection probability bounds formalized (escape e^-lambda per round).
**Rationale:** Closes A6 residual #3; feeds slashing economics not safety.
**Supersedes:** —

### DEC-042 — Theory (A6)

**Decision:** Folding soundness eps_NIFS <= 2^-128; field/hash eps <= 2^-127.
**Rationale:** End-to-end eps-budget composition theorem established.
**Supersedes:** —

### DEC-043 — Process (Doc)

**Decision:** Claims restricted to theorem scope; no extrapolation beyond proven bounds.
**Rationale:** Adversarial review discipline enforced pre-whitepaper.
**Supersedes:** —

### DEC-044 — Process (Doc)

**Decision:** Claim-hygiene amendments to abstract/intro (CA-1 through CA-5 applied).
**Rationale:** Corrects rho_E definition, continuous-state terminology, eps qualification.
**Supersedes:** —

### DEC-045 — Curves (Ch2)

**Decision:** Interop doctrine restated as lossless single-limb embedding (r_BLS < p_Pasta).
**Rationale:** Equality claims prohibited; embedding is injective with 1.78 bits headroom.
**Supersedes:** —

### DEC-046 — Process (Doc)

**Decision:** Mechanical constant pinning from reference implementation; hand-transcription banned.
**Rationale:** Transcription-by-hand is same defect class as PF-5 (domain separation).
**Supersedes:** —

### DEC-047 — Process (Doc)

**Decision:** RFC-2119 keyword convention adopted; chapters marked Normative/Informative.
**Rationale:** Document-wide enforceability of MUST/SHALL/MAY.
**Supersedes:** —

### DEC-048 — Consensus

**Decision:** CPS (Conditional Poisson) sampler pinned normatively (Algorithms 3.1-3.2).
**Rationale:** Discharges A6 residual #1; conservative WR bounds used for all stochastic claims.
**Supersedes:** A6 register

### DEC-049 — Consensus

**Decision:** Floor-aborts increment stall_counter; breaker reachable from every failure mode.
**Rationale:** Prevents livelock via sustained floor failures bypassing the breaker.
**Supersedes:** A4 behavior

### DEC-050 — Architecture

**Decision:** MSSC finality emits solely into F_E; no direct state application.
**Rationale:** Execution Monopoly Lemma coherence; only F_exec mutates state.
**Supersedes:** MSSC v0.2 pseudocode

### DEC-051 — Consensus

**Decision:** Conflict-set membership freezes at suspension; late conflicts spawn successor sets.
**Rationale:** Closes late-entry grinding channel against the beacon tie-breaker.
**Supersedes:** —

### DEC-052 — Consensus

**Decision:** Breaker ties resolved by lexicographic tx_id; total selection order guaranteed.
**Rationale:** Eliminates hash-collision ambiguity in argmax selection.
**Supersedes:** —

### DEC-053 — Crypto

**Decision:** Minimal-signature-size ciphersuite (sig G1/pk G2) + normative ABNF grammar.
**Rationale:** Signatures in G1 (48B), keys in G2 (96B); minimizes gossip bandwidth.
**Supersedes:** —

### DEC-054 — Committee

**Decision:** t: 128 -> 112 rebalance; symmetric structural margins for confidentiality + liveness.
**Rationale:** Both extremes carry >=12-seat margins; adversary-unreachable on both fronts.
**Supersedes:** DEC-028 (threshold)

### DEC-055 — Envelope

**Decision:** Mandatory sigma_user over header, intake-verified pre-decryption.
**Rationale:** Closes unauthorized debit channel (latent since M2-v0).
**Supersedes:** M2 Sec 2

### DEC-056 — Crypto

**Decision:** G2-plane ECIES/KEM-DEM; domain-separated KDF binding (X_E, header, E).
**Rationale:** Restates KEM correctly; closes unknown-key-share and cross-epoch replay.
**Supersedes:** M2 Sec 2 KEM

### DEC-057 — Doctrine

**Decision:** Early-decryption impossibility grounded in counting (m_max < t), not syntax.
**Rationale:** Corrects DEC-031 rhetoric; binding = attribution/replay-freedom, impossibility = counting.
**Supersedes:** DEC-031 (rationale)

### DEC-058 — Transport

**Decision:** Vector-committed share bundles on G1 P3 pull; permissionless aggregation.
**Rationale:** Economic efficiency for per-envelope threshold decapsulation.
**Supersedes:** —

### DEC-059 — Beacon

**Decision:** Consumption registry normative; early-knowledge inertness checked per consumer.
**Rationale:** Proves early beacon knowledge is inert for each consumer (shuffle, sortition, breaker).
**Supersedes:** —

### DEC-060 — Ordering

**Decision:** Shuffle ties resolved by lexicographic ct_hash.
**Rationale:** Deterministic total order on equal hash values.
**Supersedes:** —

### DEC-061 — Accountability

**Decision:** Simulation-determinism lemma; decree divergence = manifest-equivocation slash evidence.
**Rationale:** Catches certifier publishing statuses contradicting deterministic re-simulation.
**Supersedes:** —

### DEC-062 — Economics

**Decision:** Success fees 80% burn / 20% committee; conservation circuit-checked.
**Rationale:** Fee routing rule locked; INV-P4-5 conservation enforced arithmetically.
**Supersedes:** —

### DEC-063 — Crypto (P3)

**Decision:** WHIR-class multilinear PCS @ lambda=128; mandatory per-epoch batched GKR verification.
**Rationale:** L5 corrected to 2^-128/epoch; total eps_sys unchanged (H1's 2^-110 dominates).
**Supersedes:** DEC-042 (L5 line item)

### DEC-064 — Tables (P5)

**Decision:** Graded-cell registry: per-function certified cell widths (sigmoid 256 / tanh 128 / GELU 160 / exp 128).
**Rationale:** Machine-enumerated 1-LSB certification at registration replaces uniform-width claim.
**Supersedes:** DEC-005 (uniform-width claim)

### DEC-065 — Numerics (S1)

**Decision:** Unit-normalization constants genesis-pinned, snapshot-immutable, prover-nonselectable.
**Rationale:** Closes self-flattering self-report channel in unit selection.
**Supersedes:** DEC-019 (authority clause)

### DEC-066 — Economics

**Decision:** Reciprocal-farming disclosure (PoB degradation graceful); reserved demand-signal subsidy hook.
**Rationale:** Documents that cross-cluster farming degrades to proof-of-burn; security-neutral.
**Supersedes:** —

### DEC-067 — Accountability

**Decision:** Fidelity-report spot-audit duty; false attestation = 50%-slash evidence class.
**Rationale:** Nobody was accountable for checking fidelity_report_root claims; now slashable.
**Supersedes:** —

### DEC-068 — Numerics

**Decision:** Algorithm 5.7 normative (table-accelerated Newton + exactness certificate); iteration count non-load-bearing.
**Rationale:** Integer 10th-root algorithmically specified; correctness independent of iteration count.
**Supersedes:** DEC-015 (method clause)

---

## SECTION III — Network, Folding, and Security Composition (DEC-069 to DEC-086)

### DEC-069 — Crypto (P4)

**Decision:** Hiding semantics: succinct + witness-hiding outside declared public IO; full ZK reserved flag.
**Rationale:** "zero-knowledge-capable" language mandated; full ZK is reserved upgrade.
**Supersedes:** —

### DEC-070 — Protocol

**Decision:** Epoch = 600s nominal; checkpoints K=6 (hourly); margin table adopted.
**Rationale:** Closes epoch-length gap that bounded stall-breaker, H4 staleness, checkpoint cadence.
**Supersedes:** —

### DEC-071 — Crypto (P4)

**Decision:** Dual-layer PCS: homomorphic Pedersen accumulators (Pallas/CycleFold-Vesta) + WHIR-class wrap (lambda=128).
**Rationale:** Resolves PCS layering contradiction (HyperNova needs homomorphic; WHIR is hash-based).
**Supersedes:** DEC-063 (scope extension)

### DEC-072 — Storage (P4)

**Decision:** Normative digest schema (fixed offsets, extractable state_root).
**Rationale:** Light clients can extract state_root from opaque digest_E.
**Supersedes:** —

### DEC-073 — Economics (P4)

**Decision:** Witness-provider bonds; mechanical slash-on-bad-opening.
**Rationale:** Witness providers had duties but no bond; now slashable for malformed openings.
**Supersedes:** DEC-036 (extension)

### DEC-074 — Clients (P4)

**Decision:** Wrap mandatory; proof budget 73KB <= cap; conformance bound pre-mainnet.
**Rationale:** Proof size claim "<= 128KB" was never budgeted; now line-item budgeted.
**Supersedes:** —

### DEC-075 — Incentives (G1)

**Decision:** Shared informer-reward window (60% first / 40% next-seven-in-30s); evidence-hash dedup.
**Rationale:** First-submitter bounty was a latency lottery; now softened for fairness.
**Supersedes:** DEC-023 (distribution_clause)

### DEC-076 — Accounting (G1)

**Decision:** All byte budgets restated as rates under epoch = 600s.
**Rationale:** Absolute byte budgets predated DEC-070's 600s epoch; dimensionally stale.
**Supersedes:** G1 Sec 5 absolutes

### DEC-077 — Economics (G1)

**Decision:** Normative eps_rate EMA (per-class, 1h half-life, 1%/10min trigger); mechanical vouch-bond claims.
**Rationale:** eps_rate had no defined denominator; now per-class EMA with mechanical slashing.
**Supersedes:** —

### DEC-078 — Transport (G1)

**Decision:** QUIC-first + hole-punching + Bridge-plane fallback relays; relay multiaddr publication mandatory.
**Rationale:** No NAT/firewall traversal spec existed; now QUIC-first with fallback.
**Supersedes:** —

### DEC-079 — Scoring (G1)

**Decision:** EMA dynamics (lambda = ln2/24h), thresholds theta_gray/theta_core, bounded negative impulses; INV-G5 proof.
**Rationale:** "Half-life 24h" was asserted, never specified; now full closed-form with non-resetability proof.
**Supersedes:** —

### DEC-080 — Transport (G1)

**Decision:** Formal (ASN, /24) disjointness across R_rel+1 routes; AS-correlation residue disclosed.
**Rationale:** Path-diversity math assumed relay independence; now formalized with disclosed correlation.
**Supersedes:** —

### DEC-081 — Security

**Decision:** Annualized bound corrected to 2^-94/yr, 2^-91/decade under 600s epochs.
**Rationale:** Previous "2^-96/yr" assumed 10^4 epochs; actual is 52,596 epochs/yr.
**Supersedes:** DEC-042 (annualization)

### DEC-082 — Economics

**Decision:** Fee-only economy normative skeleton; slash-routing (bounties-first); delta_fold = 10% of committee pool.
**Rationale:** No validator income was defined; now pinned with bootstrap subsidy <=50% sunset-gated.
**Supersedes:** —

### DEC-083 — Protocol

**Decision:** Parameter-Envelope Guard: halt-not-fork on hypothesis-envelope breach at phi_0.
**Rationale:** SE-5's minimum-active-weight guard never normatively pinned; now enforced.
**Supersedes:** SE-5 (closure)

### DEC-084 — Incentives

**Decision:** delta_fold rollover on T_fold breach; publisher market permissionless.
**Rationale:** delta_fold referenced since DEC-035, valued nowhere; now pinned at 10% of pool.
**Supersedes:** DEC-035 (valuation)

### DEC-085 — Compliance

**Decision:** Value-accrual language mandate; return-representation prohibition.
**Rationale:** TOC "Wealth Generation Engine" was securities-overclaim risk; now compliant.
**Supersedes:** TOC Sec 9 wording

### DEC-086 — Process

**Decision:** CI Theorem-Reassertion Bot: parameter-touching diffs auto-reprove the composition.
**Rationale:** Operationalizes DEC-046's "theorem as code"; CI diffs the fingerprint, blocks merge on red.
**Supersedes:** —

---

## SECTION IV — Implementation and Economics Layer (DEC-087 to DEC-097)

### DEC-087 — Impl

**Decision:** t=112/n=224/halt-113 normative in all code, tests, monitors; stale-parameter diffs rejected by CI.
**Rationale:** CA-50 caught stale t=128 in liveness monitor; all code now uses DEC-054 values.
**Supersedes:** directive text (CA-50)

### DEC-088 — Crypto

**Decision:** Dual AEAD profiles (AES-256-GCM primary VAES / ChaCha20-Poly1305 fallback), profile bit + domain-separated subkeys.
**Rationale:** CA-51 caught conflict between directive's ChaCha20 and DEC-056's AES-GCM; now dual-profile.
**Supersedes:** DEC-056 (profile clause)

### DEC-089 — Perf

**Decision:** SMT throughput restated as L-bar * tau_Pose law; targets >=25k/s/core scalar, >=150k/s/core batched; Phase-1 pinning.
**Rationale:** CA-52 caught Sec 8.14 vs Sec 8.13 contradiction (120k unreachable at 20us/Poseidon); now formula-based.
**Supersedes:** Sec 8.14 flat figure

### DEC-090 — Impl

**Decision:** Integer-basis-point guard encoding; cmath/FP banned from numeric core by CI.
**Rationale:** Floating-point in guard math invites platform drift; now strictly integer.
**Supersedes:** —

### DEC-091 — Impl

**Decision:** Golden-numbers pipeline: simulator output compiles to params_golden.hpp; no prose tuning.
**Rationale:** Golden constants exit as machine artifacts, never prose; Phase-1 simulation gates mainnet.
**Supersedes:** —

### DEC-092 — Compliance

**Decision:** Claims-language filter normative; prohibited-phrase lint over all derivatives; mechanism-factual equivalents enumerated.
**Rationale:** CA-55 caught directive's hype language violating DEC-085; now enforced as lint.
**Supersedes:** DEC-085 (operationalization)

### DEC-093 — Economics

**Decision:** Revenue stack pinned: pool 20% pro-rata-by-weight among ceremony signers; delta_fold 10%; delta_info event-only.
**Rationale:** CA-56 caught directive assigning baseline yield to delta_info (wrong composition); now corrected.
**Supersedes:** directive text (CA-56)

### DEC-094 — Protocol

**Decision:** Admission governor ties phi_1 intake to fold-pipeline back-pressure; Theta = 3,495 entries/s nominal, Phase-1 pinning.
**Rationale:** CA-58 caught intake vs prover throughput mismatch (2.46M vs 2.10M entries); now back-pressure gated.
**Supersedes:** —

### DEC-095 — Economics

**Decision:** Deflation predicate normative: D(t): B(t) > G(t); bootstrap subsidy disclosed as temporary inflationary instrument with sunset gate.
**Rationale:** CA-57 caught throughput/deflation dimensional confusion; now cleanly separated.
**Supersedes:** —

### DEC-096 — Microstructure

**Decision:** HSMA-VPIN + markout study adopted as Phase-3 empirical gates; static LP-protection percentages prohibited pre-data.
**Rationale:** CA-59 caught "LPs protected" overclaim; now measurement-gated, not asserted.
**Supersedes:** Sec 8.11 (measurement program)

### DEC-097 — Simulation

**Decision:** X7 economics shard added to wind-tunnel suite with listed gates (split-neutrality, cap-binding, HHI stability, largest-remainder bias).
**Rationale:** Extends wind-tunnel to cover economics scenarios; golden constants pipeline for tuning.
**Supersedes:** DEC-091 (extension)

---

## SECTION V — Bare-Metal Implementation Steps (DEC-098 to DEC-106)

### DEC-098 — Impl/Env

**Decision:** ARM64 environment contract: LE-only, 128-B cache lines, ABI version field.
**Rationale:** Apple Silicon and ARM64 SoCs use 128-B lines; assuming 64 silently halves false-sharing protection.
**Supersedes:** —

### DEC-099 — Impl/Crypto

**Decision:** Domain-name registry centralized in params.hpp with compile-time uniqueness proof; new tags require registry insertion.
**Rationale:** PF-5 mechanized into impossibility; 33 HSM_*/IV_* strings live in one array with O(n^2) static_assert.
**Supersedes:** PF-5 (mechanization)

### DEC-100 — Process

**Decision:** PARAMS_FINGERPRINT (FNV-1a-64, canonical 37-field order) printed by all binaries; ledger-bot diff mandatory on merge.
**Rationale:** Operationalizes DEC-086's "theorem as code"; CI diffs the fingerprint, so no parameter changes without visible commit.
**Supersedes:** DEC-086 (operationalization)

### DEC-101 — Process

**Decision:** Golden slots (TAU_Q_MS, MAX_GRACE_MS) ship unpinned with GOLDEN_PARAMS_PINNED=false; mainnet tag blocked until Phase-1 flips it.
**Rationale:** Wind-tunnel outputs (DEC-091) not yet available; hardcoding would fake calibration.
**Supersedes:** DEC-091 (enforcement)

### DEC-102 — Process/Crypto

**Decision:** Constants pipeline: primes exist solely in gen_constants.py, mechanically validated (primality, 2-adicity >= 32, affine-point existence), emitted as typed constexpr headers + -D parity flags; CMake-enforced regeneration.
**Rationale:** Hand-transcription of curve constants prohibited; CMake regenerates on any generator change.
**Supersedes:** DEC-046 (operationalization)

### DEC-103 — Numerics

**Decision:** rnte_shift32 normative RNTE implementation; golden-vector contract vs Python-bigint reference is release-blocking.
**Rationale:** DEC-007's witness constraints (q, r, b) now have executable C++ implementation with golden vectors.
**Supersedes:** DEC-007 (implementation clause)

### DEC-104 — Numerics

**Decision:** Saturation semantics pinned: symmetric +/-(2^31-1) clamp, four-counter POD (SatCounters), folding relocated to consumers (layering fix).
**Rationale:** CA-64 caught SatCounters::fold() calling Poseidon from inside FP-free numeric core; now POD-only, folding moved to consumers.
**Supersedes:** Target-2 draft (asymmetric MIN clamp)

### DEC-105 — Crypto

**Decision:** Canonical Montgomery invariant [0,p) everywhere; non-canonical deserialization rejected at parse boundary (malleability closure).
**Rationale:** CA-65 caught no canonical-form policy; non-canonical deserialization enables commitment malleability.
**Supersedes:** —

### DEC-106 — Impl

**Decision:** SOS (Separated Operand Scanning) selected over CIOS for the reference kernel (carry-boundedness transparency); CIOS reclassified as Phase-1 benchmark candidate.
**Rationale:** CA-66 overrode directive's CIOS request; SOS is easier to prove carry-boundedness for, at near-identical throughput.
**Supersedes:** directive text (CA-66)

---

## SECTION VI — Poseidon, Vault, and State Backend (DEC-107 to DEC-115)

### DEC-107 — Crypto

**Decision:** Poseidon instance HSMA-P3-v1: t=3, RF=8, RP=56, alpha=5; Cauchy MDS with machine-checked minor-nonsingularity proof; RCs via SHA-256 counter DRBG (BE draws, rejection); round convention {ARK; SBOX; MIX} frozen; genesis pins instance digest.
**Rationale:** CA-68 caught conflict between "published parameterization" and derivation doctrine; now self-consistent HSMA-derived instance.
**Supersedes:** Ch.2 Sec 2.3 instantiation clause, Errata E-3

### DEC-108 — Crypto

**Decision:** IV derivation: SHA256("HSM_IV_v1"
**Rationale:**
**Supersedes:** tag

### DEC-109 — Process

**Decision:** Domain registry sole authority = generator; params.hpp Sec 8 deleted; cross-language drift structurally impossible.
**Rationale:** CA-70 caught dual-source registry drift between params.hpp and Python reference; now single authority.
**Supersedes:** Step-1 Sec 8

### DEC-110 — Impl

**Decision:** SOS carry-escape invariant: bound theorem cited in-source, debug assert + ASAN fuzz job mandated in CI.
**Rationale:** CA-69 caught SOS ripple while(carry) with no explicit upper bound guard; now bounded + fuzzed.
**Supersedes:** CA-69

### DEC-111 — Storage

**Decision:** Vault format v1: 64-B tagged entries (MID/TLEAF/REC), immutable-append segments, Empty iff handle-0 with tag-top encoding, control-sector atomic rename commits, PARAMS_FINGERPRINT binding, single-writer/multi-reader contract.
**Rationale:** Refined encoding from Target-2 blueprint; vault refuses to open under foreign protocol constants.
**Supersedes:** Target-2 blueprint (encoding refined)

### DEC-112 — Crypto/Storage

**Decision:** Leaf binding L(K,v)=Poseidon(IV_STATE_LEAF, K, v); E_0=Poseidon(IV_STATE_LEAF, 0, 0); index = canonical key low limb; record-key equality guard on every descent.
**Rationale:** CA-72 caught index-collision malleability (two accounts colliding on low 64 bits could swap payloads); now key-bound.
**Supersedes:** Sec 2.5/Sec 8.3 (Errata E-5)

### DEC-113 — Storage

**Decision:** Two-tier elision normative (empty-wedge + unchanged-subtree short-circuit with root-identity theorem); hash-before-allocate; audited stat counters; no-op writes allocate zero.
**Rationale:** CA-76 caught missing unchanged-subtree short-circuit; touching one account near dense prefix rewrote ~30 nodes needlessly; now two-tier.
**Supersedes:** Target-2 Sec I.2.4 (tier 2 added)

### DEC-114 — Impl

**Decision:** mmap strategy: fallocate->posix_fallocate->sparse fallback chain (capability logged); THP best-effort; EMPTY64 initialize-once (Errata E-4).
**Rationale:** CA-74 caught fallocate EOPNOTSUPP on FUSE/sdcard overlays; now fallback chain with capability logging.
**Supersedes:** directive text (CA-73/74)

### DEC-115 — Protocol

**Decision:** Opening-proof + independent mechanical verifier shipped at storage layer; DEC-073 witness-provider groundwork.
**Rationale:** Opens the door for bonded witness providers (DEC-073); bad openings are self-evidencing (Merkle arithmetic decides mechanically).
**Supersedes:** —

---

## Audit Finding Cross-Reference (97 Total)

### CA-Series (77 findings)
- CA-1 through CA-5: Draft review corrections -> DEC-044
- CA-6 [CRITICAL]: Theorem 2.1 false equality -> DEC-045
- CA-12 [CRITICAL]: APPLY_TO_STATE violates Execution Monopoly -> DEC-050
- CA-13 [HIGH]: A6 residual #1 sampler unpinned -> DEC-048
- CA-18 [CRITICAL]: DEC-039 broke M2 liveness -> DEC-054
- CA-19 [CRITICAL]: No user authorization signature -> DEC-055
- CA-20 [HIGH]: KEM type-invalid -> DEC-056
- CA-28 [HIGH]: L5 budget omitted PCS soundness -> DEC-063
- CA-29 [HIGH]: DEC-005 degree-2 fails certification -> DEC-064
- CA-32 [CRITICAL]: PCS layering contradiction -> DEC-071
- CA-45 [HIGH]: Annualized bound stale -> DEC-081
- CA-50 [CRITICAL]: Stale t=128 in liveness monitor -> DEC-087
- CA-55 [CRITICAL]: Directive hype language violates DEC-085 -> DEC-092
- CA-56 [HIGH]: delta_info incorrectly assigned as baseline yield -> DEC-093
- CA-68 [HIGH]: "Published parameterization" contradicts derivation -> DEC-107
- CA-70 [HIGH]: Dual-source registry drift -> DEC-109
- CA-72 [CRITICAL]: Leaf schema index-collision malleability -> DEC-112
- CA-76 [HIGH]: Missing unchanged-subtree short-circuit -> DEC-113
- (All 77 CA findings resolved)

### PF-Series (9 findings)
- PF-1 [BLOCKER]: LogUp multilinear dimension mismatch -> DEC-006
- PF-2 [BLOCKER]: Self-rejecting eps-gate bounds -> DEC-004, DEC-005
- PF-3 [HIGH]: Accumulator width overflow -> DEC-003
- PF-4 [HIGH]: RNTE tie-breaking underconstrained -> DEC-007
- PF-5 [HIGH]: arch_id string != cryptographic binding -> DEC-008
- (All 9 PF findings resolved)

### SE-Series (10 findings)
- SE-1 [CRITICAL]: Cobb-Douglas Sybil-splitting neutral -> DEC-013
- SE-2 [CRITICAL]: Cap fixpoint non-determinism -> DEC-012
- SE-4 [CRITICAL]: Self-dealing Phi farming -> DEC-014
- SE-6 [CRITICAL]: Non-canonical equivocation preimage slashes honest nodes -> DEC-016
- (All 10 SE findings resolved)

### PRE-Series (9 findings)
- PRE-1 [CRITICAL]: Phi^6*S^4 overflows scratchpad -> DEC-019
- PRE-M2-1 [CRITICAL]: M1 incompatible with commit-before-decrypt -> DEC-025
- (All 9 PRE findings resolved)

---

## Errata Register (5)

- **E-1** — log2(p) approx 254.18 is fiction; actual approx 254.0000 · _Impact:_ No theorem breaks · _Status:_ Open; generator reports true value
- **E-2** — Committee margins are 12/13, not "symmetric 12" · _Impact:_ Error direction is safe · _Status:_ Corrected in params.hpp
- **E-3** — "Published parameterization" -> "genesis-pinned HSMA-derived instance" · _Impact:_ Poseidon constants self-derived · _Status:_ DEC-107
- **E-4** — "Compile-time constexpr empty table" not achievable over runtime fe · _Impact:_ Initialize-once (~1.6ms) · _Status:_ CA-73 resolved
- **E-5** — Leaf schema did not bind hash to key · _Impact:_ Index-collision malleability · _Status:_ DEC-112 resolved

---

## A6 Theory Debt Track (6 Obligations - ALL CLOSED)

- **1. CLOSED** — Horvitz-Thompson weighted sampling concentration bounds → DEC-048 (CPS sampler pinned; WR bounds used)
- **2. CLOSED** — Hypergeometric committee election tails → DEC-054 (t=112 rebalance; ~8.7 sigma margins)
- **3. CLOSED** — Equivocation detection probability bounds → DEC-041 (escape e^-lambda per round; feeds economics not safety)
- **4. CLOSED** — Eclipse probability bounds → DEC-080 (formal (ASN,/24) disjointness)
- **5. CLOSED** — Sortition hypergeometric composition → DEC-054, DEC-059 (consumption registry proves inertness)
- **6. CLOSED** — End-to-end eps-budget composition → DEC-042, DEC-063, DEC-071, DEC-081 (eps_sys approx 2^-110/epoch, 2^-94/yr)

---

| Component | Test | Status |
|---|---|---|
| Field Arithmetic (Pallas/Vesta) | 2,472 golden vectors | PASS |
| BLS12-377 Group Law | Order #E = h1*r on 3 points | PROVEN |
| Tonelli-Shanks | 8/8 bigint equivalence | PASS |
| rand_below | Scalar field masking | PASS |
| Poseidon-3 | MDS proven, 80 RCs derived | PASS |
| RNTE Engine | 32 golden vectors | PASS |
| Scratch Accumulator | Clamp-with-counter verified | PASS |
| Sparse Merkle Tree | Canonical-at-rest verified | PASS |
| MSSC Automaton | Deterministic finality + stall-breaking | PASS |
| Mempool Gates | Conservation + replay rejection | PASS |
| Consensus Diagnostics | All 4 diagnostic checks | ALL-OK |
| DEC-090 Float-Free Lint | check_no_fp.sh returns empty | CLEAN |
| PARAMS_FINGERPRINT | FNV-1a-64 printed by all binaries | VERIFIED |
| Domain Registry | 33 names, uniqueness proven at compile-time | PROVEN |
| GATE GREEN | 6/6 conformance tests | PASSING |

---

Whitepaper v1.0 is COMPLETE and RATIFIED.
- A6 Theory Debt: ALL 6 OBLIGATIONS CLOSED
- eps_sys approx 2^-110 per epoch (assumption-dominated)
- 2^-80 design target cleared annually with 14 bits of margin
- All structural zeros (L1/L2/L4) engineered, not inherent
- C++20 reference implementation: GATE GREEN (6/6 tests)
- BLS12-377 group law: PROVEN on 3 independent points
---

## SECTION VII — IMPLEMENTATION-SESSION DECISIONS: RECOVERED FROM CODE (2026-09-04)

> Founder sighting of DEC-154/CA-134 RESOLVED: the Step-2…6 implementation sessions numbered
> decisions past 115 and cited them in C++ sources, git messages, and GATE transcripts —
> but never persisted the ledger rows. Rows below are EVIDENCE-BACKED reconstructions:
> gists verbatim from code; rationale/supersedes/finding-severity PENDING transcript ingest
> (fabrication prohibited: DEC-046/DEC-109). Gap IDs = cited nowhere = unrecoverable
> until source sessions are pasted. Code is authority (DEC-109); this register indexes it.

### DEC-116 … DEC-180 — recovered: 22 IDs; unrecovered in range: 117, 118, 120, 122, 128, 129, 132, 135, 140, 141, 142, 143, 144, 145, 147, 148, 149, 150, 151, 152, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 169, 170, 171, 173, 174, 175, 176, 177, 178, 179

#### DEC-116 — Unattributed (pending transcript)

**Evidence:** 12389d0 step4-hotfix: normative SMT scenario splice, compilable vault/update/test (DEC-116) (CONTEXT)
**Cited in:** git-log
**Status:** CITATION-RECOVERED

#### DEC-119 — Mempool/Tx (Step 5)

**Evidence:** # ══ Step 5: mempool & transaction gate (DEC-119..122) ══; //  DEC-119 money math (boundedness-proven delta) · DEC-121/123 read binding (CONTEXT)
**Cited in:** CMakeLists.txt, test_step5.cpp, tx.hpp
**Status:** CITATION-RECOVERED

#### DEC-121 — Mempool/Tx (Step 5)

**Evidence:** //  DEC-119 money math (boundedness-proven delta) · DEC-121/123 read binding; if (!(stored_key == fp::fe_to_canonical(key))) return false;   // DEC-121/123 (CONTEXT)
**Cited in:** tx.hpp
**Status:** CITATION-RECOVERED

#### DEC-123 — Vault/SMT (Step 4)

**Evidence:** // DEC-112 leaf binding · DEC-113 elision · DEC-123 canonical keys at rest; const fp::fe ck = fp::fe_to_canonical(key);        // DEC-123 (CONTEXT)
**Cited in:** diag_step5.cpp, whitepaper.tex, update.hpp, +1f
**Status:** CITATION-RECOVERED

#### DEC-124 — Conformance

**Evidence:** // (DEC-124 contract). Batches designed so sorted order == push order where (CONTEXT)
**Cited in:** test_step5.cpp
**Status:** CITATION-RECOVERED

#### DEC-125 — Unattributed (pending transcript)

**Evidence:** // DEC-125/162: whole-file authorship; field proofs BEFORE curve work. (CONTEXT)
**Cited in:** bls_derive.cpp
**Status:** CITATION-RECOVERED

#### DEC-126 — Vault/SMT (Step 4)

**Evidence:** // DEC-126 slot schema: payload = 126/1/64/1 = 192 bits (exact 24-B window); fc53442 step5-hotfix3: memset-after-tag root cause closed, 192-bit slot schema (E-6), canonical-at-rest restored, tag-aware diagnostics (DEC-126/127) (CONTEXT)
**Cited in:** update.hpp, git-log
**Status:** CITATION-RECOVERED

#### DEC-127 — Vault/SMT (Step 4)

**Evidence:** {} only (GIST)
**Cited in:** diag_step5.cpp, update.hpp
**Status:** CITATION-RECOVERED

#### DEC-130 — Unattributed (pending transcript)

**Evidence:** f9c691c step5-green-final: CA-96 orphan-var + CA-97 type-hygiene fixed, gate.sh institutionalized (DEC-130/131) (CONTEXT)
**Cited in:** git-log
**Status:** CITATION-RECOVERED

#### DEC-131 — Pipeline/Gate

**Evidence:** # HSMA VERIFICATION GATE v5 (DEC-131/132/140/154): (CONTEXT)
**Cited in:** gate.sh
**Status:** CITATION-RECOVERED

#### DEC-133 — Vault/SMT (Step 4)

**Evidence:** // CONTRACT (DEC-134, supersedes DEC-133): expected_root is a RAW DIGEST — (CONTEXT)
**Cited in:** update.hpp
**Status:** CITATION-RECOVERED

#### DEC-134 — Vault/SMT (Step 4)

**Evidence:** proofs verify against the RAW DIGEST — no fe, no conversions, (GIST)
**Cited in:** test_step4.cpp, update.hpp, git-log
**Status:** CITATION-RECOVERED

#### DEC-136 — Consensus (Step 6)

**Evidence:** # ══ Step 6: MSSC automaton (DEC-136..139) ══; // HSMA :: consensus.hpp — MSSC automaton, corrected (DEC-136..141) (CONTEXT)
**Cited in:** CMakeLists.txt, consensus.hpp, gen_constants.py
**Status:** CITATION-RECOVERED

#### DEC-137 — Consensus (Step 6)

**Evidence:** std::size_t lead = 0;                          // DEC-137 (CONTEXT)
**Cited in:** consensus.hpp
**Status:** CITATION-RECOVERED

#### DEC-138 — Consensus (Step 6)

**Evidence:** if (lhs < rhs) {                                   // DEC-138 / E-7 (CONTEXT)
**Cited in:** consensus.hpp
**Status:** CITATION-RECOVERED

#### DEC-139 — Pipeline

**Evidence:** """Realized-trace goldens (DEC-139) with CA-120 brace law enforced."""; i)Hz@Realized-trace goldens (DEC-139) with CA-120 brace law enforced.cPRPRV44PR4 (CONTEXT)
**Cited in:** gen_constants.cpython-314.pyc, gen_constants.py
**Status:** CITATION-RECOVERED

#### DEC-146 — Pipeline

**Evidence:** # ── BRACE LAW v3 (DEC-146): grammar-aware, compiler-aligned ── (CONTEXT)
**Cited in:** gen_constants.py
**Status:** CITATION-RECOVERED

#### DEC-153 — Conformance

**Evidence:** initial opinion is harness input (GIST)
**Cited in:** test_step6.cpp
**Status:** CITATION-RECOVERED

#### DEC-154 — Unattributed (pending transcript)

**Evidence:** fd9d4c3 step6-final-green: gate v5 clean-first (CA-134/DEC-154), seedpref verified idempotent (CA-135) — Step 6 CLOSED at 6/6 (CONTEXT)
**Cited in:** git-log
**Status:** CITATION-RECOVERED

#### DEC-168 — Unattributed (pending transcript)

**Evidence:** silence can never masquerade as a hang (GIST)
**Cited in:** bls_derive.cpp
**Status:** CITATION-RECOVERED

#### DEC-172 — Unattributed (pending transcript)

**Evidence:** // DEC-172 SINGLE-DIVISION LAW: the /3 already happened (xsq->h1). (CONTEXT)
**Cited in:** bls_derive.cpp
**Status:** CITATION-RECOVERED

#### DEC-180 — Unattributed (pending transcript)

**Evidence:** const fe6 C8=madd(QC,C4,C4);                       // EXACTLY 8C (DEC-180) (CONTEXT)
**Cited in:** bls_derive.cpp
**Status:** CITATION-RECOVERED

### CA-78 … CA-135 — recovered: 12 IDs

- **CA-80** — naive sum wraps to 0 (GIST) · _Cited in:_ test_step5.cpp · _Status:_ CITATION-RECOVERED
- **CA-81** — credit crosses ceiling (GIST) · _Cited in:_ test_step5.cpp · _Status:_ CITATION-RECOVERED
- **CA-86** — // ── EARLY REGRESSION ANCHOR (CA-86): reads must work BEFORE any mempool op; "post-seed lookup (CA-86 regression anchor)"); (CONTEXT) · _Cited in:_ test_step5.cpp · _Status:_ CITATION-RECOVERED
- **CA-96** — f9c691c step5-green-final: CA-96 orphan-var + CA-97 type-hygiene fixed, gate.sh institutionalized (DEC-130/131) (CONTEXT) · _Cited in:_ git-log · _Status:_ CITATION-RECOVERED
- **CA-97** — f9c691c step5-green-final: CA-96 orphan-var + CA-97 type-hygiene fixed, gate.sh institutionalized (DEC-130/131) (CONTEXT) · _Cited in:_ git-log · _Status:_ CITATION-RECOVERED
- **CA-105** — 75e7227 step4-openings-green-final: roots cross boundaries as raw digests (DEC-134), call-site inventory doctrine, kill CA-105 class (CONTEXT) · _Cited in:_ git-log · _Status:_ CITATION-RECOVERED
- **CA-112** — // ---- seed: exactly 159 bytes, 15-byte tag (CA-112/113) ---- (CONTEXT) · _Cited in:_ consensus.hpp · _Status:_ CITATION-RECOVERED
- **CA-113** — exact 57 (GIST) · _Cited in:_ consensus.hpp · _Status:_ CITATION-RECOVERED
- **CA-114** — /// CA-114 fix: stagger derives from H(beacon ‖ CONFLICT) — matching the (CONTEXT) · _Cited in:_ consensus.hpp · _Status:_ CITATION-RECOVERED
- **CA-120** — """Realized-trace goldens (DEC-139) with CA-120 brace law enforced."""; i)Hz@Realized-trace goldens (DEC-139) with CA-120 brace law enforced.cPRPRV44PR4 (CONTEXT) · _Cited in:_ gen_constants.cpython-314.pyc, gen_constants.py · _Status:_ CITATION-RECOVERED
- **CA-134** — fd9d4c3 step6-final-green: gate v5 clean-first (CA-134/DEC-154), seedpref verified idempotent (CA-135) — Step 6 CLOSED at 6/6 (CONTEXT) · _Cited in:_ git-log · _Status:_ CITATION-RECOVERED
- **CA-135** — fd9d4c3 step6-final-green: gate v5 clean-first (CA-134/DEC-154), seedpref verified idempotent (CA-135) — Step 6 CLOSED at 6/6 (CONTEXT) · _Cited in:_ git-log · _Status:_ CITATION-RECOVERED

### Semantic anchors (unambiguous, from code evidence)
- **DEC-153** (test_step6.cpp ×2, gist verbatim: "initial opinion is harness input"): consensus Automaton is a PURE function — View.preference is explicit caller input, no internal default — required for bit-exact golden-trace replay (extends DEC-091/102 to consensus).
- **DEC-123** (GATE verdict: "canonical-at-rest (DEC-123 held)"): vault stores canonical-form entries at rest; invariant machine-verified (extends DEC-105 to storage).

### Restore protocol
Paste the Step-2…6 implementation-session transcripts (chats that produced these IDs) →
adversarial verification → full rows replace CITATION-RECOVERED status. Until then, no
rationale is invented for any row above.

---

## RECONCILIATION REGISTER — 2026-09-04

> APPEND-ONLY (DEC-046/109/043). Historical rows above are never rewritten; corrections
> travel as errata.

### Errata E-6 — DEC-ID collisions: DEC-038 canonical = floor invariant φ_floor > f/α (whitepaper §4.3); G1 row re-designated **DEC-038-G1**. DEC-039 canonical = structural floor m_adv ≤ 100 < t (§7.3/§10.4); A6 row re-designated **DEC-039-A6**. Historical rows preserved.
### Errata E-7 — ε line items: authoritative = whitepaper.tex v1.0 final (DEC-063/071): L5=2⁻¹²⁸, L6=2⁻¹²⁷; merged-edition 2⁻¹⁹³/2⁻¹⁹⁶ superseded; ε_sys ≈ 2⁻¹¹⁰/epoch unchanged (H1-dominated).
### Errata E-8 — committee: **t=112 of n=224, halt=113** (DEC-054→DEC-087); margins 12/13 (E-2). Whitepaper patched same commit; DEC-028 row stands as history.
### Errata E-9 — notation: DEC-004 sigmoid domain ±2^8 ("±28" = superscript-flattening artifact); RC-#8 canonical: sc-loop Pmul cost > 90s timeout (fixtures 30→3); tonelli_q-loop hypothesis instrumented, NOT confirmed.

### CA-R Series — reconciliation findings

- **CA-R1 · 🟠 HIGH** — t=128 prose drift vs DEC-054/087 → **Errata E-8 + tex patch**
- **CA-R2 · 🟠 HIGH** — DEC-038/039 dual assignments → **Errata E-6**
- **CA-R3 · 🟠 HIGH** — Founder sighting DEC-154/CA-134 unexplained → ****RESOLVED 2026-09-04**: citations in C++ sources/git (Section VII)**
- **CA-R4 · 🟠 HIGH** — Prior push heredoc truncated → **Never executed (parse error pre-write); replaced by this script**
- **CA-R5 · 🟡 MED** — ε line-item drift between editions → **Errata E-7**
- **CA-R6 · 🔵 LOW** — Notation ambiguities → **Errata E-9**
- **CA-R7 · 🟠 HIGH** — **Process defect (this session): INSPECT grep filtered \*.md/\*.txt only — missed \*.cpp/\*.hpp citations; produced false "max=DEC-115" conclusion** → **Full-spectrum harvest (all file types + git log) is now mandatory for any ledger range query**

### Phase Status Pin (DEC-089/091/094/096/101)
**PHASE 0 — IN PROGRESS.** Done: Steps 1–6 kernels GATE GREEN 6/6 (incl. full-trace
consensus conformance C1/C2/C3, breaker/stagger parity, vault opening-proof negative
tests, 10th-root engine). Remaining: threshold module (DKG/beacon/order-bound shares),
G1 transport, HyperNova NIVC circuit, φ₀–φ₇ integration. PHASE 1 NOT ENTERED
(gate: GOLDEN_PARAMS_PINNED=false, DEC-101). PHASE 3: HSMA-VPIN/markout (DEC-096).

---

## SECTION VII — A — Semantic Anchors (evidence-derived, 2026-09-04, commit 87a3731)

> Derived verbatim from code citations + git commit messages (H1/H2 harvest).
> Content = exactly what the evidence states; rationale pending source-session ingest.
> No fabrication (DEC-046/109).

#### DEC-116

**Anchor:** Step-4 hotfix: normative SMT scenario splice; compilable vault/update/test
**Evidence:** commit 12389d0

#### DEC-119

**Anchor:** Money math = boundedness-proven delta; COST_OVERFLOW / CREDIT_OVERFLOW rejected; all-or-nothing application (no half-applied debit)
**Evidence:** tx.hpp:3 · test_step5.cpp:82-100

#### DEC-121

**Anchor:** Read binding: stored_key == fe_to_canonical(key) on every read
**Evidence:** tx.hpp:51

#### DEC-123

**Anchor:** Canonical-at-rest: keys stored canonical, never Montgomery; gate machine-checks the verdict string
**Evidence:** update.hpp:125 · diag_step5.cpp:54 · gate.sh:32 · whitepaper.tex:566

#### DEC-124

**Anchor:** Batch contract: sorted order == push order
**Evidence:** test_step5.cpp:2

#### DEC-125

**Anchor:** Whole-file authorship; field proofs BEFORE curve work
**Evidence:** bls_derive.cpp:2

#### DEC-126

**Anchor:** Slot schema: payload = 126\|1\|64\|1 = 192 bits, exact 24-B window. SUPERSEDES whitepaper 199-bit leaf schema (Errata E-11)
**Evidence:** update.hpp:3-4 · commit fc53442

#### DEC-127

**Anchor:** Init law: aggregate-init only ({}) — memset after member assignment is a violation (TAG SEVERED)
**Evidence:** update.hpp:4,126,132,157 · diag_step5.cpp:51

#### DEC-130

**Anchor:** gate.sh institutionalized
**Evidence:** commit f9c691c · gate.sh:2

#### DEC-131

**Anchor:** Verification-gate authority (v5 header cites DEC-131/132/140/154)
**Evidence:** gate.sh:2

#### DEC-133

**Anchor:** Superseded root-passing contract (see DEC-134)
**Evidence:** update.hpp:207

#### DEC-134

**Anchor:** Roots cross module boundaries as RAW DIGESTS — no fe, no conversions; call-site inventory doctrine; kills CA-105 class
**Evidence:** update.hpp:207 · test_step4.cpp:84 · commit 75e7227

#### DEC-136

**Anchor:** Corrected MSSC automaton family begins (Step 6: DEC-136..141)
**Evidence:** consensus.hpp:1 · CMakeLists.txt:108

#### DEC-137

**Anchor:** Lead-scan rule
**Evidence:** consensus.hpp:145

#### DEC-138

**Anchor:** Comparison-branch rule (tied to Step-6 session errata E-7)
**Evidence:** consensus.hpp:142

#### DEC-139

**Anchor:** Realized-trace goldens in generator (CA-120 brace law enforced)
**Evidence:** gen_constants.py:427,523

#### DEC-146

**Anchor:** BRACE LAW v3: grammar-aware, compiler-aligned emitted code
**Evidence:** gen_constants.py:604

#### DEC-153

**Anchor:** Automaton purity: initial opinion is harness input (no internal default) — enables bit-exact golden replay
**Evidence:** test_step6.cpp:50,89

#### DEC-154

**Anchor:** GATE v5 clean-first — no ghost artifacts survive a run
**Evidence:** gate.sh:2 · commit fd9d4c3

#### DEC-168

**Anchor:** Silence can never masquerade as a hang — unbuffered stdout mandated
**Evidence:** bls_derive.cpp:404

#### DEC-172

**Anchor:** Single-division law: /3 folded into constant (xsq->h1)
**Evidence:** bls_derive.cpp:180

#### DEC-180

**Anchor:** The 8C doubling fix (C8 = madd(QC,C4,C4)) — Root Cause #7 institutionalized as a decision
**Evidence:** bls_derive.cpp:359

- **CA-80** — Naive sum wraps to 0 (HALF+HALF) — COST_OVERFLOW regression · _Evidence:_ test_step5.cpp:82,90
- **CA-81** — Credit crosses ceiling — CREDIT_OVERFLOW regression · _Evidence:_ test_step5.cpp:83,91
- **CA-86** — Reads must work BEFORE any mempool op — early-read regression anchor · _Evidence:_ test_step5.cpp:48,51
- **CA-96** — Step-5: orphan-variable hygiene · _Evidence:_ commit f9c691c
- **CA-97** — Step-5: type hygiene · _Evidence:_ commit f9c691c
- **CA-105** — Root boundary-conversion defect class — killed by DEC-134 · _Evidence:_ commit 75e7227
- **CA-112** — Beacon seed exactly 159 B, 15-B tag · _Evidence:_ consensus.hpp:94
- **CA-113** — Beacon hash input exactly 57 B (17+8+32) · _Evidence:_ consensus.hpp:196
- **CA-114** — Stagger derives from H(beacon ‖ CONFLICT) — parity fix · _Evidence:_ consensus.hpp:162
- **CA-120** — Brace law enforced on emitted goldens · _Evidence:_ gen_constants.py:523
- **CA-134** — Gate v5 clean-first · _Evidence:_ commit fd9d4c3
- **CA-135** — seedpref (seed-preference) verified idempotent · _Evidence:_ commit fd9d4c3

**Range/slash-implied IDs** (assigned; content pending transcript): DEC-120, DEC-122 (DEC-119..122); DEC-132, DEC-140 (gate.sh v5 header); DEC-141 (DEC-136..141); DEC-162 (DEC-125/162).

**Cross-session consistency:** DEC-112/DEC-113 citations in update.hpp match ledger rows DEC-112/DEC-113 exactly — the 115-row record and Step-4 code agree. Highest cited: **DEC-180 / CA-135**.

---

## RECONCILIATION REGISTER — ADDENDUM (second pass, 2026-09-04)

#### Errata E-10 — errata-namespace collision (CA-R8)
Reconciliation Register E-6/E-7 collide with session-local errata: Step-5 E-6 = 192-bit slot schema (commit fc53442); Step-6 E-7 = automaton erratum (consensus.hpp:142, gen_constants.py:427; content pending). Resolution: reconciliation errata re-designated **ER-6..ER-9** (the earlier labels below stand as history); canonical E-6 = Step-5 slot schema; canonical E-7 = Step-6 erratum.

#### Errata E-11 — whitepaper leaf-schema staleness (CA-R9)
Whitepaper §2.6/§8.3: (mbal[126]‖sbal[1]‖nonce[64]‖flags[8]) = 199 bits. Code DEC-126: 126|1|64|1 = 192 bits, exact 24-B window. Code is authority (DEC-109 doctrine); tex patched in same commit; flags width 8→1.

#### CA-R addendum (second pass)

- **CA-R8 · 🟠 HIGH** — Errata ID collision: reconciliation E-6/E-7 vs session-local E-6/E-7 → **E-10 re-designation ER-6..ER-9**
- **CA-R9 · 🟠 HIGH** — Whitepaper leaf schema 199-bit/flags[8] vs code DEC-126 192-bit/flags[1] → **E-11 + tex patch**
- **CA-R10 · 🔵 LOW** — Harvest-script SyntaxWarning (\* escape) — cosmetic, output correct → **raw strings in future scripts**
- **CA-R11 · 🔵 LOW** — First harvest regex matched only DEC-prefixed tokens; slash/range IDs missed → **VII-A range-implied list**

#### Status
Pushed: 87a3731 (Section VII: 22 DEC + 12 CA citation-recovered; ER-6..ER-9; Phase-0 pin; tex t=112 sync).
True citation ceiling: **DEC-180 / CA-135**. GATE GREEN 6/6 maintained.

---

## STRUCTURE NOTE (CA-R12 — closed 2026-09-04)

Rebuilt to one uniform format: single `#` title · `##` sections · `###` subsections ·
ledger-status table · table of contents · every table isolated by blank lines (GitHub
render guarantee) · no Python-repr artifacts · no mega-line headers.

**Content unchanged** — every DEC/CA/PF/SE/PRE identifier present before the rebuild is
present after it (machine-verified; backup kept alongside). Defects closed: three
authoring generations (original ledger + two append passes) had mixed heading levels
and table shapes; the status header was one unreadable line; evidence lists printed as
`116, 119, 121`.

---

> **RENDER-FORMAT v3.1 (CA-R13/R14/R15 — closed 2026-09-04).** (1) A binary NUL byte —
> embedded by the code-citation harvest — made GitHub treat this file as binary and show
> raw unrendered text; all binary/control bytes are now stripped and the file is
> machine-verified pure text. (2) Wide multi-column tables were replaced by ADR-style
> blocks and severity-badged one-liners (mobile-readable). (3) ID-coverage check is
> zero-pad-insensitive. Content unchanged: every DEC/CA/PF/SE/PRE identifier present.
> Backup: `docs/DECISIONS.md.pre-v31.<ts>` (removed after push; git history is canonical).

---

> **RENDER-FORMAT v3.1 (CA-R13/R14/R15 — closed 2026-09-04).** (1) A binary NUL byte —
> embedded by the code-citation harvest — made GitHub treat this file as binary and show
> raw unrendered text; all binary/control bytes are now stripped and the file is
> machine-verified pure text. (2) Wide multi-column tables were replaced by ADR-style
> blocks and severity-badged one-liners (mobile-readable). (3) ID-coverage check is
> zero-pad-insensitive. Content unchanged: every DEC/CA/PF/SE/PRE identifier present.
> Backup: `docs/DECISIONS.md.pre-v31.<ts>` (removed after push; git history is canonical).

---

## WHITEPAPER FINAL-AUDIT PASS — CA-R16 Series (2026-09-04)

| ID | Sev | Finding | Resolution |
|---|---|---|---|
| CA-R16 | HIGH | §10.4 listed validations for unbuilt modules (threshold decapsulation, PC-edge SAT, graded-cell repro, light-client sync, HHI guard, σ_user) alongside implemented ones | Status-split inserted: items 1–4, 8 = machine-validated (6/6); 5–7, 9–11 = release gates pending modules |
| CA-R17 | HIGH | §2.6 leaf schema 199-bit/flags[8] — Errata E-11/DEC-126 never landed in tex | Applied: 192-bit/flags[1], exact 24-B window |
| CA-R18 | MED | Appendix + repo tree "39 decisions" stale | 115 verified + recovered to DEC-180 |
| CA-R19 | MED | Abstract "constant-size" vs CA-5/DEC-044 | "Succinct, size independent of transaction count" |
| CA-R20 | MED | Informer reward pre-DEC-075 | Shared window 60/40 in 30 s |
| CA-R21 | MED | Version/date not bumped | v1.0.1, 2026-09-04 |
| CA-R22 | MED | Root causes #8/#10 absent | Evidence-level entries added |
| CA-R23 | MED | Definition 1 "syntactically bound" vs DEC-057 | Enforcement clause reworded (counting) |
| CA-R24 | LOW | Notation nits (12/13 render, bits/nats, PoW phrasing, δ_fold value) | Applied |

**E-8 verification:** t=112 confirmed at 8 locations in the final PDF. **E-11 status: APPLIED** (was recorded-only).

---
### PATCH-MECHANICS ERRATUM — CA-R25…R30 (2026-09-04)

Three consecutive whitepaper patch scripts FATALed or mis-wrote the same §2.6 leaf-schema
line. All root causes auditor-side; forensic diff confirms every exact-string and
structural-anchor edit landed cleanly while the sole regex-touched line was destroyed.
- **CA-R25 · 🟠 HIGH** — Sequencing: 18f2472 + register rows declared patches "APPLIED"
  before the tex write was verified; write then aborted. Corrected by the follow-up commit.
- **CA-R26 · 🟡 MED** — Patterns authored from PDF-extracted text; source is LaTeX macros.
- **CA-R27 · 🟠 HIGH** — On-FATAL restore branch was dead code; canonical restore is
  `git checkout -- <file>`.
- **CA-R28 · 🟡 MED** — 199-replacement lazy capture ate "bits" and unbalanced math
  delimiters (forensic-diff confirmed).
- **CA-R29 · 🟠 HIGH** — `re.sub` with a FUNCTION replacement does not process `\g<1>`
  backreferences: literal `\text{\g<1>1\]` written into the working file (uncompilable
  LaTeX). Caught by read-back verify; never reached a commit.
- **CA-R30 · 🟠 HIGH** — Repair script's idempotency gate keyed on "Errata Sync v1.0.1",
  a string the aborted write had already inserted — repair would have skipped and pushed
  the mangled file. Neutralized by truncated paste.

**Doctrine (permanent, three strikes):** exact-literal replacement + whole-phrase read-back
for known lines; regex only for structural section insertions; `git checkout` as the only
restore; idempotency gates test the DEFECT, never a version string.

---

### CA-R36 - BROKEN ASSERT DIAGNOSTIC + DEAD IDEMPOTENCY GATE (2026-09-04, LOW)

FIXDB re-run crashed with TypeError instead of a clean message: the assert message
contained a literal '%s' ('= { %s };') colliding with %-formatting. Idempotency gate
checked for the string 'CA-R35', which never exists in gen_constants.py - the gate
could never trigger, so double-runs crash instead of skip. Also: standalone header
check wrote to /tmp (not writable in Termux) - checks must use the build/ directory.
No damage; the brace fix itself had already landed. Doctrine: diagnostics are code -
format them safely (f-strings), and idempotency gates must test the DEFECT, not a
marker string.

## SECTION VIII - Phase-0 Threshold Module (Step 7 - 2026-09-04)

#### DEC-181 - Threshold module decomposition (Steps 7-10)
**Decision:** Step 7: F_r scalar kernel + golden parity. Step 8: promote E(F_q) from tools/bls_derive.cpp into include/hsma/threshold/ + hash-to-curve. Step 9: DKG (Feldman G1), threshold BLS signing, epoch beacon (HSM_BEACON_V1), order-bound shares, DLEQ. Step 10: pairing verifier + epoch-header certificate checks.
**Rationale:** Pairing deferral sound per DEC-032/034 (out-of-circuit, one check per epoch header); Feldman verification pairing-free; conformance validates vs harness secrets until Step 10.
**Supersedes:** N/A

#### DEC-182 - F_r representation and constants authority
**Decision:** 4x64-limb Montgomery, canonical [0,r) (DEC-105 mirror), CIOS multiply with conditional subtraction; constants from gen_constants.py STEP 7: r = documented BLS12-377 scalar, verified against kernel literals via x^4-x^2+1 == r with x = 0x8508c00000000001 (provenance embedded in emitted header), MR-52 validated, 253-bit.
**Rationale:** No hand transcription (DEC-046/102); value-anchored extraction (CA-R32 doctrine); r < 2^253 gives 3 bits headroom (DEC-045).
**Supersedes:** N/A

#### DEC-183 - Scalar golden parity is release-blocking
**Decision:** 64 SHA-256-counter DRBG pairs, add/sub/mul/inv parity vs Python big-int; edges (0, 1, r-1, r rejected); n=5/t=3 DKG scalar trace (shares, Lagrange-at-zero, reconstruction) with tamper divergence asserted at generation.
**Rationale:** Extends DEC-091/103 golden pipeline: machine ground truth, no prose tuning.
**Supersedes:** N/A

#### DEC-184 - DKG scalar semantics (Step 7 slice)
**Decision:** Degree-(t-1) polys over F_r, Horner, id domain {1..n}, Lagrange-at-zero; tamper detection via reconstruction divergence + share re-derivation. Feldman curve side lands Step 9.
**Rationale:** Separates verifiable scalar kernel from curve integration; both golden-pinned.
**Supersedes:** N/A

**Build status:** step7_conformance (suite 7/7). consensus.hpp / bls_derive.cpp untouched: sim_beacon replacement = Step 9; E(F_q) promotion = Step 8.
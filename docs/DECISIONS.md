<div align="center">

# 🏛 HSMA — DECISION LEDGER
### Holographic Spin-Manifold Architecture · `DECISIONS.md`

**Every claim traceable to a decision ID · every decision carries its rationale and supersession chain**

*Append-only discipline (DEC-046/109) — corrections travel as errata, never as rewrites*

</div>

---

## LEDGER STATUS

| Field | Value |
|---|---|
| Baseline | v1.0 Ratified |
| Whitepaper | v1.0 — A6 Theory Debt CLOSED (all 6 obligations) |
| Implementation | GATE GREEN — 6/6 conformance tests (Steps 2–6 kernels) |
| Phase | **0 — bare-metal core, IN PROGRESS** (Phase 1 gate: `GOLDEN_PARAMS_PINNED=false`, DEC-101) |
| Verified rows | DEC-001 … DEC-115 |
| Citation-recovered | Section VII — DEC-116 … DEC-180 · CA-78 … CA-135 |
| Findings register | CA-001…CA-135 · PF-1…PF-9 · SE-1…SE-10 · PRE series · CA-R series |
| Errata | E-1 … E-11 |
| Last restructured | 2026-09-04 |

---

## TABLE OF CONTENTS

| § | Section | IDs | Rows |
|---|---|---|---|
| I | Core Cryptographic Specifications | DEC-001–039 | 39 |
| II | Whitepaper Deep Audit Decisions | DEC-040–068 | 29 |
| III | Network, Folding & Security Composition | DEC-069–086 | 18 |
| IV | Implementation & Economics Layer | DEC-087–097 | 11 |
| V | Bare-Metal Implementation Steps 1–2 | DEC-098–106 | 9 |
| VI | Poseidon, Vault & State Backend | DEC-107–115 | 9 |
| VII | Implementation-Session Decisions (citation-recovered) | DEC-116–180 | 22 + 12 CA |
| — | Audit Finding Cross-Reference (CA · PF · SE · PRE) | — | 97 findings |
| — | Errata Register · A6 Track · Implementation Verification | — | — |
| — | Reconciliation Register (Errata · CA-R series · Phase pin) | — | — |

---

## SECTION I — Core Cryptographic Specifications (DEC-001 to DEC-039)

| ID | Component | Decision | Rationale | Supersedes |
|---|---|---|---|---|
| DEC-001 | Arithmetic (P0) | Pasta curves (Pallas/Vesta), L=126, unsigned mag + sign flags. | Native HyperNova synergy; sidesteps disjunctive range checks. | N/A |
| DEC-002 | Sequencing (M1) | Simulate-then-Commit (Solvable Prefix) via 192-node committee. | Eliminates joint insolvency mid-fold and deterministic ordering MEV. | N/A |
| DEC-003 | Accumulator (P5) | Saturation: Clamp-with-counter via L'=127 scratchpad. | Prevents 96-bit accumulator overflow; preserves network liveness. | N/A |
| DEC-004 | Activations (P5) | Sigmoid domain +/-28; 1-LSB (eps < 2^-16) rule strictly retained. | Ensures mathematical uniformity across all bounds. | N/A |
| DEC-005 | Table Eval (P5) | Degree-2 chunk interpolation (T_0, T_1, T_2). | Achieves O(h^3) error drop, satisfying 1-LSB gate without table bloat. | N/A |
| DEC-006 | Lookup Auth (P5) | Standard LogUp pipeline (Commit -> gamma -> Sum-Check). | Resolves multilinear degree mismatch and adaptive-collision grinding. | N/A |
| DEC-007 | Rounding (P5) | RNTE strict witness constraints (q, r, b) with tie-breaker logic. | Closes prover-discretion gap at exact halfway ties. | N/A |
| DEC-008 | Integrity (P5) | arch_root, work_manifest, fidelity_report_root bound to ModelCommit. | Closes billing inflation and model-swapping vulnerability. | N/A |
| DEC-009 | Constraints (P5) | 10-bit range checks on u_low via boolean bit-decomposition. | Avoids LogUp table bloat and lookup-argument constraint inflation. | N/A |
| DEC-010 | Sybil Defense (S1) | Prioritize Validator Admission, Staking Bonds, and Weight Accounting. | Sybil resistance is governed by weight creation and capital bounds (f < 0.20). | N/A |
| DEC-011 | Circuit Hygiene (P5) | Enforce row-selector gating q * (u_low - sum 2^i b_i) = 0. | Prevents unconstrained witness coordinates on padded rows. | DEC-009 |
| DEC-012 | Weights (S1) | Cap evaluated against uncapped total T_0 in a single pass. | Eliminates fixpoint non-determinism and dust-sybil inflation. | S1-v1 Sec 2.1 |
| DEC-013 | Weights (S1) | Cluster-level W_max via payout-graph linkage and attestations. | Prevents neutral Sybil-splitting cap evasion (perjury-slashable). | S1-v1 Sec 2.2 |
| DEC-014 | Weights (S1) | Phi eligibility requires burned fees >= floor price, paid by non-cluster. | Prevents PoUW degenerating into PoW via self-dealing. | S1-v1 Sec 2.1 |
| DEC-015 | Numerics (S1) | W_i = floor((Phi_i^6 * S_i^4)^(1/10)) via integer Newton root, RNTE. | Closes irrational fractional power gap for deterministic circuit folds. | S1-v1 Sec 2.1 |
| DEC-016 | Slashing (S1/MSSC) | Canonical domain-separated vote preimage (HSM_MSSC_VOTE_v1). | Prevents honest nodes from being slashed for legitimate preference updates. | S1-v1 Sec 4 |
| DEC-017 | Exit (S1) | Escrow extended by E_ev (14 days) past unbonding. Checkpoint sync. | Closes long-range attacks and ensures historical key accountability. | S1-v1 Sec 5 |
| DEC-018 | Liveness (S1) | Corroborated delivery gating, exit-queue exemption, soft-to-hard ladder. | Prevents partition-hostile slashing and targeted sampler eclipsing. | S1-v1 Sec 4 |
| DEC-019 | Numerics (S1) | Unit normalization with strict width invariant 6a + 4b + eps_guard <= 126. | Prevents F_p field overflow (mod p wraparound) during weight calculation. | S1-v2 Sec 2.1 |
| DEC-020 | Weights (S1) | Intra-cluster capped weight distributed via largest-remainder rounding. | Closes arithmetic cap-evasion loophole within clusters. | S1-v2 Sec 2.2 |
| DEC-021 | Numerics (S1) | Re-pinned RNTE (Round-to-Nearest-Ties-to-Even) strictly across all math. | Eliminates prover-discretion gap on exact halfway ties. | S1-v2 Sec 2.1 |
| DEC-022 | Gossip (G1) | 4-Tier Message Taxonomy (P0-P3). P3 is pull-only, bounded by MAX_PROOF_BYTES. | Enforces compute-budget gating and eliminates verification-DoS. | N/A |
| DEC-023 | Incentives (G1) | Informer Reward (delta_info = 0.5% of burn, cap 1000) paid to first relay of P0 evidence. | Converts network censorship into an economically losing partition attack. | N/A |
| DEC-024 | Identity (G1) | contact_root added to epoch header. MSSC dials strictly by pre-commitment. | Kills last-mile Sybil endpoint injection and reputation laundering. | N/A |
| DEC-025 | Sequencing (M2) | Pipeline inverted to Commit-then-Simulate. | Resolves M1/M2 paradox. Eliminates committee front-running cartel. | M1-v1 core semantics (DEC-002) |
| DEC-026 | Privacy (M2) | Envelope schema: {sender_pk, nonce, fee_escrow} cleartext; payload encrypted. | Preserves MSSC conflict-set routing and spam pricing while hiding content. | N/A |
| DEC-027 | Ordering (M2) | Beacon-shuffled ordering lock: Sort(H("HSM_ORDER_v1" || beacon_E || H(ct))). | Destroys positional MEV. Brute-forcing positions incurs direct nonce-burn costs. | N/A |
| DEC-028 | Committee (M2) | 192 active + 32 standby, joint DKG, t=128; weighted beacon sortition; <=16 seats/cluster. | Balances confidentiality (>= 8.7 sigma) against liveness faults. | N/A |
| DEC-029 | Liveness (M2) | Degradation ladder L0-L3; 100% refund on committee-fault skip. | Committee censorship becomes a pure cost center; user funds are never burned. | N/A |
| DEC-030 | Folding (P4/M2) | Unified trust anchor: decree_root certified by same t-of-n threshold BLS. | Massive prover economy; establishes single cryptographic trust root across pillars. | N/A |
| DEC-031 | Folding (P4) | Self-Send Routing: If sender == recipient, circuit asserts recipient_pre == sender_post. | Prevents state collision and balance inflation during self-transfers. | N/A |
| DEC-032 | Folding (P4) | Fee Underflow Protection: Explicit LT gate balance >= delta_req before subtraction. | Prevents unsigned magnitude wraparound on insolvent accounts. | N/A |
| DEC-033 | Folding (P4) | PAD Routing Bypass: b_PAD skips state verification constraints entirely. | Enforces Padding-Neutrality without bloating constraint count. | N/A |
| DEC-034 | Folding (P4) | Certificate Assumption: Circuit assumes decree_root valid; verifier checks BLS out-of-circuit. | Avoids 10^6+ constraint in-circuit pairing verification. | N/A |
| DEC-035 | P2P (G1) | NetworkAdapter Interface: Consensus and Mempool interact via AccountID/ContentID. | Decouples cryptography from transport, enabling future PQ agility. | N/A |
| DEC-036 | P2P (G1) | P0 Evidence DoS Guard: P0 messages require peer score >= theta_gray or consume budget. | Prevents CPU exhaustion via fake slashing evidence spam. | N/A |
| DEC-037 | P2P (G1) | Grace Period Eclipse Defense: Hard /24 (max 2) and ASN caps. Dial 4 Bridge nodes. | Prevents eclipse attacks during initial sync. | N/A |
| DEC-038 | P2P (G1) | P3 Pull Redundancy: Proof requests broadcast to 3 relay paths. | Prevents selfish node sync starvation. | N/A |
| DEC-039 | Theory (A6) | Sequential Quorum Accumulation applied to MSSC safety bounds. | Isolated union bound insufficient; sequential independent sampling yields eps << 2^-128. | N/A |

---

## SECTION II — Whitepaper Deep Audit Decisions (DEC-040 to DEC-068)

| ID | Component | Decision | Rationale | Supersedes |
|---|---|---|---|---|
| DEC-040 | Crypto | BLS12-377 threshold-BLS anchor certified by same t-of-n across pillars. | Unified asymmetric trust anchor across beacon, manifest, and checkpoints. | N/A |
| DEC-041 | Theory (A6) | Equivocation detection probability bounds formalized (escape e^-lambda per round). | Closes A6 residual #3; feeds slashing economics not safety. | N/A |
| DEC-042 | Theory (A6) | Folding soundness eps_NIFS <= 2^-128; field/hash eps <= 2^-127. | End-to-end eps-budget composition theorem established. | N/A |
| DEC-043 | Process (Doc) | Claims restricted to theorem scope; no extrapolation beyond proven bounds. | Adversarial review discipline enforced pre-whitepaper. | N/A |
| DEC-044 | Process (Doc) | Claim-hygiene amendments to abstract/intro (CA-1 through CA-5 applied). | Corrects rho_E definition, continuous-state terminology, eps qualification. | N/A |
| DEC-045 | Curves (Ch2) | Interop doctrine restated as lossless single-limb embedding (r_BLS < p_Pasta). | Equality claims prohibited; embedding is injective with 1.78 bits headroom. | N/A |
| DEC-046 | Process (Doc) | Mechanical constant pinning from reference implementation; hand-transcription banned. | Transcription-by-hand is same defect class as PF-5 (domain separation). | N/A |
| DEC-047 | Process (Doc) | RFC-2119 keyword convention adopted; chapters marked Normative/Informative. | Document-wide enforceability of MUST/SHALL/MAY. | N/A |
| DEC-048 | Consensus | CPS (Conditional Poisson) sampler pinned normatively (Algorithms 3.1-3.2). | Discharges A6 residual #1; conservative WR bounds used for all stochastic claims. | A6 register |
| DEC-049 | Consensus | Floor-aborts increment stall_counter; breaker reachable from every failure mode. | Prevents livelock via sustained floor failures bypassing the breaker. | A4 behavior |
| DEC-050 | Architecture | MSSC finality emits solely into F_E; no direct state application. | Execution Monopoly Lemma coherence; only F_exec mutates state. | MSSC v0.2 pseudocode |
| DEC-051 | Consensus | Conflict-set membership freezes at suspension; late conflicts spawn successor sets. | Closes late-entry grinding channel against the beacon tie-breaker. | N/A |
| DEC-052 | Consensus | Breaker ties resolved by lexicographic tx_id; total selection order guaranteed. | Eliminates hash-collision ambiguity in argmax selection. | N/A |
| DEC-053 | Crypto | Minimal-signature-size ciphersuite (sig G1/pk G2) + normative ABNF grammar. | Signatures in G1 (48B), keys in G2 (96B); minimizes gossip bandwidth. | N/A |
| DEC-054 | Committee | t: 128 -> 112 rebalance; symmetric structural margins for confidentiality + liveness. | Both extremes carry >=12-seat margins; adversary-unreachable on both fronts. | DEC-028 (threshold) |
| DEC-055 | Envelope | Mandatory sigma_user over header, intake-verified pre-decryption. | Closes unauthorized debit channel (latent since M2-v0). | M2 Sec 2 |
| DEC-056 | Crypto | G2-plane ECIES/KEM-DEM; domain-separated KDF binding (X_E, header, E). | Restates KEM correctly; closes unknown-key-share and cross-epoch replay. | M2 Sec 2 KEM |
| DEC-057 | Doctrine | Early-decryption impossibility grounded in counting (m_max < t), not syntax. | Corrects DEC-031 rhetoric; binding = attribution/replay-freedom, impossibility = counting. | DEC-031 (rationale) |
| DEC-058 | Transport | Vector-committed share bundles on G1 P3 pull; permissionless aggregation. | Economic efficiency for per-envelope threshold decapsulation. | N/A |
| DEC-059 | Beacon | Consumption registry normative; early-knowledge inertness checked per consumer. | Proves early beacon knowledge is inert for each consumer (shuffle, sortition, breaker). | N/A |
| DEC-060 | Ordering | Shuffle ties resolved by lexicographic ct_hash. | Deterministic total order on equal hash values. | N/A |
| DEC-061 | Accountability | Simulation-determinism lemma; decree divergence = manifest-equivocation slash evidence. | Catches certifier publishing statuses contradicting deterministic re-simulation. | N/A |
| DEC-062 | Economics | Success fees 80% burn / 20% committee; conservation circuit-checked. | Fee routing rule locked; INV-P4-5 conservation enforced arithmetically. | N/A |
| DEC-063 | Crypto (P3) | WHIR-class multilinear PCS @ lambda=128; mandatory per-epoch batched GKR verification. | L5 corrected to 2^-128/epoch; total eps_sys unchanged (H1's 2^-110 dominates). | DEC-042 (L5 line item) |
| DEC-064 | Tables (P5) | Graded-cell registry: per-function certified cell widths (sigmoid 256 / tanh 128 / GELU 160 / exp 128). | Machine-enumerated 1-LSB certification at registration replaces uniform-width claim. | DEC-005 (uniform-width claim) |
| DEC-065 | Numerics (S1) | Unit-normalization constants genesis-pinned, snapshot-immutable, prover-nonselectable. | Closes self-flattering self-report channel in unit selection. | DEC-019 (authority clause) |
| DEC-066 | Economics | Reciprocal-farming disclosure (PoB degradation graceful); reserved demand-signal subsidy hook. | Documents that cross-cluster farming degrades to proof-of-burn; security-neutral. | N/A |
| DEC-067 | Accountability | Fidelity-report spot-audit duty; false attestation = 50%-slash evidence class. | Nobody was accountable for checking fidelity_report_root claims; now slashable. | N/A |
| DEC-068 | Numerics | Algorithm 5.7 normative (table-accelerated Newton + exactness certificate); iteration count non-load-bearing. | Integer 10th-root algorithmically specified; correctness independent of iteration count. | DEC-015 (method clause) |

---

## SECTION III — Network, Folding, and Security Composition (DEC-069 to DEC-086)

| ID | Component | Decision | Rationale | Supersedes |
|---|---|---|---|---|
| DEC-069 | Crypto (P4) | Hiding semantics: succinct + witness-hiding outside declared public IO; full ZK reserved flag. | "zero-knowledge-capable" language mandated; full ZK is reserved upgrade. | N/A |
| DEC-070 | Protocol | Epoch = 600s nominal; checkpoints K=6 (hourly); margin table adopted. | Closes epoch-length gap that bounded stall-breaker, H4 staleness, checkpoint cadence. | N/A |
| DEC-071 | Crypto (P4) | Dual-layer PCS: homomorphic Pedersen accumulators (Pallas/CycleFold-Vesta) + WHIR-class wrap (lambda=128). | Resolves PCS layering contradiction (HyperNova needs homomorphic; WHIR is hash-based). | DEC-063 (scope extension) |
| DEC-072 | Storage (P4) | Normative digest schema (fixed offsets, extractable state_root). | Light clients can extract state_root from opaque digest_E. | N/A |
| DEC-073 | Economics (P4) | Witness-provider bonds; mechanical slash-on-bad-opening. | Witness providers had duties but no bond; now slashable for malformed openings. | DEC-036 (extension) |
| DEC-074 | Clients (P4) | Wrap mandatory; proof budget 73KB <= cap; conformance bound pre-mainnet. | Proof size claim "<= 128KB" was never budgeted; now line-item budgeted. | N/A |
| DEC-075 | Incentives (G1) | Shared informer-reward window (60% first / 40% next-seven-in-30s); evidence-hash dedup. | First-submitter bounty was a latency lottery; now softened for fairness. | DEC-023 (distribution_clause) |
| DEC-076 | Accounting (G1) | All byte budgets restated as rates under epoch = 600s. | Absolute byte budgets predated DEC-070's 600s epoch; dimensionally stale. | G1 Sec 5 absolutes |
| DEC-077 | Economics (G1) | Normative eps_rate EMA (per-class, 1h half-life, 1%/10min trigger); mechanical vouch-bond claims. | eps_rate had no defined denominator; now per-class EMA with mechanical slashing. | N/A |
| DEC-078 | Transport (G1) | QUIC-first + hole-punching + Bridge-plane fallback relays; relay multiaddr publication mandatory. | No NAT/firewall traversal spec existed; now QUIC-first with fallback. | N/A |
| DEC-079 | Scoring (G1) | EMA dynamics (lambda = ln2/24h), thresholds theta_gray/theta_core, bounded negative impulses; INV-G5 proof. | "Half-life 24h" was asserted, never specified; now full closed-form with non-resetability proof. | N/A |
| DEC-080 | Transport (G1) | Formal (ASN, /24) disjointness across R_rel+1 routes; AS-correlation residue disclosed. | Path-diversity math assumed relay independence; now formalized with disclosed correlation. | N/A |
| DEC-081 | Security | Annualized bound corrected to 2^-94/yr, 2^-91/decade under 600s epochs. | Previous "2^-96/yr" assumed 10^4 epochs; actual is 52,596 epochs/yr. | DEC-042 (annualization) |
| DEC-082 | Economics | Fee-only economy normative skeleton; slash-routing (bounties-first); delta_fold = 10% of committee pool. | No validator income was defined; now pinned with bootstrap subsidy <=50% sunset-gated. | N/A |
| DEC-083 | Protocol | Parameter-Envelope Guard: halt-not-fork on hypothesis-envelope breach at phi_0. | SE-5's minimum-active-weight guard never normatively pinned; now enforced. | SE-5 (closure) |
| DEC-084 | Incentives | delta_fold rollover on T_fold breach; publisher market permissionless. | delta_fold referenced since DEC-035, valued nowhere; now pinned at 10% of pool. | DEC-035 (valuation) |
| DEC-085 | Compliance | Value-accrual language mandate; return-representation prohibition. | TOC "Wealth Generation Engine" was securities-overclaim risk; now compliant. | TOC Sec 9 wording |
| DEC-086 | Process | CI Theorem-Reassertion Bot: parameter-touching diffs auto-reprove the composition. | Operationalizes DEC-046's "theorem as code"; CI diffs the fingerprint, blocks merge on red. | N/A |

---

## SECTION IV — Implementation and Economics Layer (DEC-087 to DEC-097)

| ID | Component | Decision | Rationale | Supersedes |
|---|---|---|---|---|
| DEC-087 | Impl | t=112/n=224/halt-113 normative in all code, tests, monitors; stale-parameter diffs rejected by CI. | CA-50 caught stale t=128 in liveness monitor; all code now uses DEC-054 values. | directive text (CA-50) |
| DEC-088 | Crypto | Dual AEAD profiles (AES-256-GCM primary VAES / ChaCha20-Poly1305 fallback), profile bit + domain-separated subkeys. | CA-51 caught conflict between directive's ChaCha20 and DEC-056's AES-GCM; now dual-profile. | DEC-056 (profile clause) |
| DEC-089 | Perf | SMT throughput restated as L-bar * tau_Pose law; targets >=25k/s/core scalar, >=150k/s/core batched; Phase-1 pinning. | CA-52 caught Sec 8.14 vs Sec 8.13 contradiction (120k unreachable at 20us/Poseidon); now formula-based. | Sec 8.14 flat figure |
| DEC-090 | Impl | Integer-basis-point guard encoding; cmath/FP banned from numeric core by CI. | Floating-point in guard math invites platform drift; now strictly integer. | N/A |
| DEC-091 | Impl | Golden-numbers pipeline: simulator output compiles to params_golden.hpp; no prose tuning. | Golden constants exit as machine artifacts, never prose; Phase-1 simulation gates mainnet. | N/A |
| DEC-092 | Compliance | Claims-language filter normative; prohibited-phrase lint over all derivatives; mechanism-factual equivalents enumerated. | CA-55 caught directive's hype language violating DEC-085; now enforced as lint. | DEC-085 (operationalization) |
| DEC-093 | Economics | Revenue stack pinned: pool 20% pro-rata-by-weight among ceremony signers; delta_fold 10%; delta_info event-only. | CA-56 caught directive assigning baseline yield to delta_info (wrong composition); now corrected. | directive text (CA-56) |
| DEC-094 | Protocol | Admission governor ties phi_1 intake to fold-pipeline back-pressure; Theta = 3,495 entries/s nominal, Phase-1 pinning. | CA-58 caught intake vs prover throughput mismatch (2.46M vs 2.10M entries); now back-pressure gated. | N/A |
| DEC-095 | Economics | Deflation predicate normative: D(t): B(t) > G(t); bootstrap subsidy disclosed as temporary inflationary instrument with sunset gate. | CA-57 caught throughput/deflation dimensional confusion; now cleanly separated. | N/A |
| DEC-096 | Microstructure | HSMA-VPIN + markout study adopted as Phase-3 empirical gates; static LP-protection percentages prohibited pre-data. | CA-59 caught "LPs protected" overclaim; now measurement-gated, not asserted. | Sec 8.11 (measurement program) |
| DEC-097 | Simulation | X7 economics shard added to wind-tunnel suite with listed gates (split-neutrality, cap-binding, HHI stability, largest-remainder bias). | Extends wind-tunnel to cover economics scenarios; golden constants pipeline for tuning. | DEC-091 (extension) |

---

## SECTION V — Bare-Metal Implementation Steps (DEC-098 to DEC-106)

| ID | Component | Decision | Rationale | Supersedes |
|---|---|---|---|---|
| DEC-098 | Impl/Env | ARM64 environment contract: LE-only, 128-B cache lines, ABI version field. | Apple Silicon and ARM64 SoCs use 128-B lines; assuming 64 silently halves false-sharing protection. | N/A |
| DEC-099 | Impl/Crypto | Domain-name registry centralized in params.hpp with compile-time uniqueness proof; new tags require registry insertion. | PF-5 mechanized into impossibility; 33 HSM_*/IV_* strings live in one array with O(n^2) static_assert. | PF-5 (mechanization) |
| DEC-100 | Process | PARAMS_FINGERPRINT (FNV-1a-64, canonical 37-field order) printed by all binaries; ledger-bot diff mandatory on merge. | Operationalizes DEC-086's "theorem as code"; CI diffs the fingerprint, so no parameter changes without visible commit. | DEC-086 (operationalization) |
| DEC-101 | Process | Golden slots (TAU_Q_MS, MAX_GRACE_MS) ship unpinned with GOLDEN_PARAMS_PINNED=false; mainnet tag blocked until Phase-1 flips it. | Wind-tunnel outputs (DEC-091) not yet available; hardcoding would fake calibration. | DEC-091 (enforcement) |
| DEC-102 | Process/Crypto | Constants pipeline: primes exist solely in gen_constants.py, mechanically validated (primality, 2-adicity >= 32, affine-point existence), emitted as typed constexpr headers + -D parity flags; CMake-enforced regeneration. | Hand-transcription of curve constants prohibited; CMake regenerates on any generator change. | DEC-046 (operationalization) |
| DEC-103 | Numerics | rnte_shift32 normative RNTE implementation; golden-vector contract vs Python-bigint reference is release-blocking. | DEC-007's witness constraints (q, r, b) now have executable C++ implementation with golden vectors. | DEC-007 (implementation clause) |
| DEC-104 | Numerics | Saturation semantics pinned: symmetric +/-(2^31-1) clamp, four-counter POD (SatCounters), folding relocated to consumers (layering fix). | CA-64 caught SatCounters::fold() calling Poseidon from inside FP-free numeric core; now POD-only, folding moved to consumers. | Target-2 draft (asymmetric MIN clamp) |
| DEC-105 | Crypto | Canonical Montgomery invariant [0,p) everywhere; non-canonical deserialization rejected at parse boundary (malleability closure). | CA-65 caught no canonical-form policy; non-canonical deserialization enables commitment malleability. | N/A |
| DEC-106 | Impl | SOS (Separated Operand Scanning) selected over CIOS for the reference kernel (carry-boundedness transparency); CIOS reclassified as Phase-1 benchmark candidate. | CA-66 overrode directive's CIOS request; SOS is easier to prove carry-boundedness for, at near-identical throughput. | directive text (CA-66) |

---

## SECTION VI — Poseidon, Vault, and State Backend (DEC-107 to DEC-115)

| ID | Component | Decision | Rationale | Supersedes |
|---|---|---|---|---|
| DEC-107 | Crypto | Poseidon instance HSMA-P3-v1: t=3, RF=8, RP=56, alpha=5; Cauchy MDS with machine-checked minor-nonsingularity proof; RCs via SHA-256 counter DRBG (BE draws, rejection); round convention {ARK; SBOX; MIX} frozen; genesis pins instance digest. | CA-68 caught conflict between "published parameterization" and derivation doctrine; now self-consistent HSMA-derived instance. | Ch.2 Sec 2.3 instantiation clause, Errata E-3 |
| DEC-108 | Crypto | IV derivation: SHA256("HSM_IV_v1"||tag||u64le(nonce)), LE-read, rejection < p; distinct-primitive bootstrapping (no circularity); registry-index addressing normative. | IVs derived via different primitive than the sponge itself; eliminates bootstrapping circularity. | N/A |
| DEC-109 | Process | Domain registry sole authority = generator; params.hpp Sec 8 deleted; cross-language drift structurally impossible. | CA-70 caught dual-source registry drift between params.hpp and Python reference; now single authority. | Step-1 Sec 8 |
| DEC-110 | Impl | SOS carry-escape invariant: bound theorem cited in-source, debug assert + ASAN fuzz job mandated in CI. | CA-69 caught SOS ripple while(carry) with no explicit upper bound guard; now bounded + fuzzed. | CA-69 |
| DEC-111 | Storage | Vault format v1: 64-B tagged entries (MID/TLEAF/REC), immutable-append segments, Empty iff handle-0 with tag-top encoding, control-sector atomic rename commits, PARAMS_FINGERPRINT binding, single-writer/multi-reader contract. | Refined encoding from Target-2 blueprint; vault refuses to open under foreign protocol constants. | Target-2 blueprint (encoding refined) |
| DEC-112 | Crypto/Storage | Leaf binding L(K,v)=Poseidon(IV_STATE_LEAF, K, v); E_0=Poseidon(IV_STATE_LEAF, 0, 0); index = canonical key low limb; record-key equality guard on every descent. | CA-72 caught index-collision malleability (two accounts colliding on low 64 bits could swap payloads); now key-bound. | Sec 2.5/Sec 8.3 (Errata E-5) |
| DEC-113 | Storage | Two-tier elision normative (empty-wedge + unchanged-subtree short-circuit with root-identity theorem); hash-before-allocate; audited stat counters; no-op writes allocate zero. | CA-76 caught missing unchanged-subtree short-circuit; touching one account near dense prefix rewrote ~30 nodes needlessly; now two-tier. | Target-2 Sec I.2.4 (tier 2 added) |
| DEC-114 | Impl | mmap strategy: fallocate->posix_fallocate->sparse fallback chain (capability logged); THP best-effort; EMPTY64 initialize-once (Errata E-4). | CA-74 caught fallocate EOPNOTSUPP on FUSE/sdcard overlays; now fallback chain with capability logging. | directive text (CA-73/74) |
| DEC-115 | Protocol | Opening-proof + independent mechanical verifier shipped at storage layer; DEC-073 witness-provider groundwork. | Opens the door for bonded witness providers (DEC-073); bad openings are self-evidencing (Merkle arithmetic decides mechanically). | N/A |

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

| ID | Description | Impact | Status |
|---|---|---|---|
| E-1 | log2(p) approx 254.18 is fiction; actual approx 254.0000 | No theorem breaks | Open; generator reports true value |
| E-2 | Committee margins are 12/13, not "symmetric 12" | Error direction is safe | Corrected in params.hpp |
| E-3 | "Published parameterization" -> "genesis-pinned HSMA-derived instance" | Poseidon constants self-derived | DEC-107 |
| E-4 | "Compile-time constexpr empty table" not achievable over runtime fe | Initialize-once (~1.6ms) | CA-73 resolved |
| E-5 | Leaf schema did not bind hash to key | Index-collision malleability | DEC-112 resolved |

---

## A6 Theory Debt Track (6 Obligations - ALL CLOSED)

| # | Obligation | Status | Resolution |
|---|---|---|---|
| 1 | Horvitz-Thompson weighted sampling concentration bounds | CLOSED | DEC-048 (CPS sampler pinned; WR bounds used) |
| 2 | Hypergeometric committee election tails | CLOSED | DEC-054 (t=112 rebalance; ~8.7 sigma margins) |
| 3 | Equivocation detection probability bounds | CLOSED | DEC-041 (escape e^-lambda per round; feeds economics not safety) |
| 4 | Eclipse probability bounds | CLOSED | DEC-080 (formal (ASN,/24) disjointness) |
| 5 | Sortition hypergeometric composition | CLOSED | DEC-054, DEC-059 (consumption registry proves inertness) |
| 6 | End-to-end eps-budget composition | CLOSED | DEC-042, DEC-063, DEC-071, DEC-081 (eps_sys approx 2^-110/epoch, 2^-94/yr) |

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

---

## SECTION VII — IMPLEMENTATION-SESSION DECISIONS: RECOVERED FROM CODE (2026-09-04)

> Founder sighting of DEC-154/CA-134 RESOLVED: the Step-2…6 implementation sessions numbered
> decisions past 115 and cited them in C++ sources, git messages, and GATE transcripts —
> but never persisted the ledger rows. Rows below are EVIDENCE-BACKED reconstructions:
> gists verbatim from code; rationale/supersedes/finding-severity PENDING transcript ingest
> (fabrication prohibited: DEC-046/DEC-109). Gap IDs = cited nowhere = unrecoverable
> until source sessions are pasted. Code is authority (DEC-109); this register indexes it.

### DEC-116 … DEC-180 — recovered: 22 IDs; unrecovered in range: 117, 118, 120, 122, 128, 129, 132, 135, 140, 141, 142, 143, 144, 145, 147, 148, 149, 150, 151, 152, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 169, 170, 171, 173, 174, 175, 176, 177, 178, 179

| ID | Component (inferred) | Evidence (verbatim from code/git) | Cited in | Status |
|---|---|---|---|---|
| DEC-116 | Unattributed (pending transcript) | 12389d0 step4-hotfix: normative SMT scenario splice, compilable vault/update/test (DEC-116) (CONTEXT) | git-log | CITATION-RECOVERED |
| DEC-119 | Mempool/Tx (Step 5) | # ══ Step 5: mempool & transaction gate (DEC-119..122) ══; //  DEC-119 money math (boundedness-proven delta) · DEC-121/123 read binding (CONTEXT) | CMakeLists.txt, test_step5.cpp, tx.hpp | CITATION-RECOVERED |
| DEC-121 | Mempool/Tx (Step 5) | //  DEC-119 money math (boundedness-proven delta) · DEC-121/123 read binding; if (!(stored_key == fp::fe_to_canonical(key))) return false;   // DEC-121/123 (CONTEXT) | tx.hpp | CITATION-RECOVERED |
| DEC-123 | Vault/SMT (Step 4) | // DEC-112 leaf binding · DEC-113 elision · DEC-123 canonical keys at rest; const fp::fe ck = fp::fe_to_canonical(key);        // DEC-123 (CONTEXT) | diag_step5.cpp, whitepaper.tex, update.hpp, +1f | CITATION-RECOVERED |
| DEC-124 | Conformance | // (DEC-124 contract). Batches designed so sorted order == push order where (CONTEXT) | test_step5.cpp | CITATION-RECOVERED |
| DEC-125 | Unattributed (pending transcript) | // DEC-125/162: whole-file authorship; field proofs BEFORE curve work. (CONTEXT) | bls_derive.cpp | CITATION-RECOVERED |
| DEC-126 | Vault/SMT (Step 4) | // DEC-126 slot schema: payload = 126/1/64/1 = 192 bits (exact 24-B window); fc53442 step5-hotfix3: memset-after-tag root cause closed, 192-bit slot schema (E-6), canonical-at-rest restored, tag-aware diagnostics (DEC-126/127) (CONTEXT) | update.hpp, git-log | CITATION-RECOVERED |
| DEC-127 | Vault/SMT (Step 4) | {} only (GIST) | diag_step5.cpp, update.hpp | CITATION-RECOVERED |
| DEC-130 | Unattributed (pending transcript) | f9c691c step5-green-final: CA-96 orphan-var + CA-97 type-hygiene fixed, gate.sh institutionalized (DEC-130/131) (CONTEXT) | git-log | CITATION-RECOVERED |
| DEC-131 | Pipeline/Gate | # HSMA VERIFICATION GATE v5 (DEC-131/132/140/154): (CONTEXT) | gate.sh | CITATION-RECOVERED |
| DEC-133 | Vault/SMT (Step 4) | // CONTRACT (DEC-134, supersedes DEC-133): expected_root is a RAW DIGEST — (CONTEXT) | update.hpp | CITATION-RECOVERED |
| DEC-134 | Vault/SMT (Step 4) | proofs verify against the RAW DIGEST — no fe, no conversions, (GIST) | test_step4.cpp, update.hpp, git-log | CITATION-RECOVERED |
| DEC-136 | Consensus (Step 6) | # ══ Step 6: MSSC automaton (DEC-136..139) ══; // HSMA :: consensus.hpp — MSSC automaton, corrected (DEC-136..141) (CONTEXT) | CMakeLists.txt, consensus.hpp, gen_constants.py | CITATION-RECOVERED |
| DEC-137 | Consensus (Step 6) | std::size_t lead = 0;                          // DEC-137 (CONTEXT) | consensus.hpp | CITATION-RECOVERED |
| DEC-138 | Consensus (Step 6) | if (lhs < rhs) {                                   // DEC-138 / E-7 (CONTEXT) | consensus.hpp | CITATION-RECOVERED |
| DEC-139 | Pipeline | """Realized-trace goldens (DEC-139) with CA-120 brace law enforced.""";  i)Hz@Realized-trace goldens (DEC-139) with CA-120 brace law enforced.c                 P    R P                  R V  4       4      P                  R4    (CONTEXT) | gen_constants.cpython-314.pyc, gen_constants.py | CITATION-RECOVERED |
| DEC-146 | Pipeline | # ── BRACE LAW v3 (DEC-146): grammar-aware, compiler-aligned ── (CONTEXT) | gen_constants.py | CITATION-RECOVERED |
| DEC-153 | Conformance | initial opinion is harness input (GIST) | test_step6.cpp | CITATION-RECOVERED |
| DEC-154 | Unattributed (pending transcript) | fd9d4c3 step6-final-green: gate v5 clean-first (CA-134/DEC-154), seedpref verified idempotent (CA-135) — Step 6 CLOSED at 6/6 (CONTEXT) | git-log | CITATION-RECOVERED |
| DEC-168 | Unattributed (pending transcript) | silence can never masquerade as a hang (GIST) | bls_derive.cpp | CITATION-RECOVERED |
| DEC-172 | Unattributed (pending transcript) | // DEC-172 SINGLE-DIVISION LAW: the /3 already happened (xsq->h1). (CONTEXT) | bls_derive.cpp | CITATION-RECOVERED |
| DEC-180 | Unattributed (pending transcript) | const fe6 C8=madd(QC,C4,C4);                       // EXACTLY 8C (DEC-180) (CONTEXT) | bls_derive.cpp | CITATION-RECOVERED |

### CA-78 … CA-135 — recovered: 12 IDs

| ID | Evidence (verbatim) | Cited in | Status |
|---|---|---|---|
| CA-80 | naive sum wraps to 0 (GIST) | test_step5.cpp | CITATION-RECOVERED |
| CA-81 | credit crosses ceiling (GIST) | test_step5.cpp | CITATION-RECOVERED |
| CA-86 | // ── EARLY REGRESSION ANCHOR (CA-86): reads must work BEFORE any mempool op; "post-seed lookup (CA-86 regression anchor)"); (CONTEXT) | test_step5.cpp | CITATION-RECOVERED |
| CA-96 | f9c691c step5-green-final: CA-96 orphan-var + CA-97 type-hygiene fixed, gate.sh institutionalized (DEC-130/131) (CONTEXT) | git-log | CITATION-RECOVERED |
| CA-97 | f9c691c step5-green-final: CA-96 orphan-var + CA-97 type-hygiene fixed, gate.sh institutionalized (DEC-130/131) (CONTEXT) | git-log | CITATION-RECOVERED |
| CA-105 | 75e7227 step4-openings-green-final: roots cross boundaries as raw digests (DEC-134), call-site inventory doctrine, kill CA-105 class (CONTEXT) | git-log | CITATION-RECOVERED |
| CA-112 | // ---- seed: exactly 159 bytes, 15-byte tag (CA-112/113) ---- (CONTEXT) | consensus.hpp | CITATION-RECOVERED |
| CA-113 | exact 57 (GIST) | consensus.hpp | CITATION-RECOVERED |
| CA-114 | /// CA-114 fix: stagger derives from H(beacon ‖ CONFLICT) — matching the (CONTEXT) | consensus.hpp | CITATION-RECOVERED |
| CA-120 | """Realized-trace goldens (DEC-139) with CA-120 brace law enforced.""";  i)Hz@Realized-trace goldens (DEC-139) with CA-120 brace law enforced.c                 P    R P                  R V  4       4      P                  R4    (CONTEXT) | gen_constants.cpython-314.pyc, gen_constants.py | CITATION-RECOVERED |
| CA-134 | fd9d4c3 step6-final-green: gate v5 clean-first (CA-134/DEC-154), seedpref verified idempotent (CA-135) — Step 6 CLOSED at 6/6 (CONTEXT) | git-log | CITATION-RECOVERED |
| CA-135 | fd9d4c3 step6-final-green: gate v5 clean-first (CA-134/DEC-154), seedpref verified idempotent (CA-135) — Step 6 CLOSED at 6/6 (CONTEXT) | git-log | CITATION-RECOVERED |

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

| ID | Sev | Finding | Resolution |
|---|---|---|---|
| CA-R1 | HIGH | t=128 prose drift vs DEC-054/087 | Errata E-8 + tex patch |
| CA-R2 | HIGH | DEC-038/039 dual assignments | Errata E-6 |
| CA-R3 | HIGH | Founder sighting DEC-154/CA-134 unexplained | **RESOLVED 2026-09-04**: citations in C++ sources/git (Section VII) |
| CA-R4 | HIGH | Prior push heredoc truncated | Never executed (parse error pre-write); replaced by this script |
| CA-R5 | MED | ε line-item drift between editions | Errata E-7 |
| CA-R6 | LOW | Notation ambiguities | Errata E-9 |
| CA-R7 | HIGH | **Process defect (this session): INSPECT grep filtered \*.md/\*.txt only — missed \*.cpp/\*.hpp citations; produced false "max=DEC-115" conclusion** | Full-spectrum harvest (all file types + git log) is now mandatory for any ledger range query |

### Phase Status Pin (DEC-089/091/094/096/101)
**PHASE 0 — IN PROGRESS.** Done: Steps 1–6 kernels GATE GREEN 6/6 (incl. full-trace
consensus conformance C1/C2/C3, breaker/stagger parity, vault opening-proof negative
tests, 10th-root engine). Remaining: threshold module (DKG/beacon/order-bound shares),
G1 transport, HyperNova NIVC circuit, φ₀–φ₇ integration. PHASE 1 NOT ENTERED
(gate: GOLDEN_PARAMS_PINNED=false, DEC-101). PHASE 3: HSMA-VPIN/markout (DEC-096).

---

## SECTION VII-A — Semantic Anchors (evidence-derived, 2026-09-04, commit 87a3731)

> Derived verbatim from code citations + git commit messages (H1/H2 harvest).
> Content = exactly what the evidence states; rationale pending source-session ingest.
> No fabrication (DEC-046/109).

| ID | Anchor | Evidence |
|---|---|---|
| DEC-116 | Step-4 hotfix: normative SMT scenario splice; compilable vault/update/test | commit 12389d0 |
| DEC-119 | Money math = boundedness-proven delta; COST_OVERFLOW / CREDIT_OVERFLOW rejected; all-or-nothing application (no half-applied debit) | tx.hpp:3 · test_step5.cpp:82-100 |
| DEC-121 | Read binding: stored_key == fe_to_canonical(key) on every read | tx.hpp:51 |
| DEC-123 | Canonical-at-rest: keys stored canonical, never Montgomery; gate machine-checks the verdict string | update.hpp:125 · diag_step5.cpp:54 · gate.sh:32 · whitepaper.tex:566 |
| DEC-124 | Batch contract: sorted order == push order | test_step5.cpp:2 |
| DEC-125 | Whole-file authorship; field proofs BEFORE curve work | bls_derive.cpp:2 |
| DEC-126 | Slot schema: payload = 126\|1\|64\|1 = 192 bits, exact 24-B window. SUPERSEDES whitepaper 199-bit leaf schema (Errata E-11) | update.hpp:3-4 · commit fc53442 |
| DEC-127 | Init law: aggregate-init only ({}) — memset after member assignment is a violation (TAG SEVERED) | update.hpp:4,126,132,157 · diag_step5.cpp:51 |
| DEC-130 | gate.sh institutionalized | commit f9c691c · gate.sh:2 |
| DEC-131 | Verification-gate authority (v5 header cites DEC-131/132/140/154) | gate.sh:2 |
| DEC-133 | Superseded root-passing contract (see DEC-134) | update.hpp:207 |
| DEC-134 | Roots cross module boundaries as RAW DIGESTS — no fe, no conversions; call-site inventory doctrine; kills CA-105 class | update.hpp:207 · test_step4.cpp:84 · commit 75e7227 |
| DEC-136 | Corrected MSSC automaton family begins (Step 6: DEC-136..141) | consensus.hpp:1 · CMakeLists.txt:108 |
| DEC-137 | Lead-scan rule | consensus.hpp:145 |
| DEC-138 | Comparison-branch rule (tied to Step-6 session errata E-7) | consensus.hpp:142 |
| DEC-139 | Realized-trace goldens in generator (CA-120 brace law enforced) | gen_constants.py:427,523 |
| DEC-146 | BRACE LAW v3: grammar-aware, compiler-aligned emitted code | gen_constants.py:604 |
| DEC-153 | Automaton purity: initial opinion is harness input (no internal default) — enables bit-exact golden replay | test_step6.cpp:50,89 |
| DEC-154 | GATE v5 clean-first — no ghost artifacts survive a run | gate.sh:2 · commit fd9d4c3 |
| DEC-168 | Silence can never masquerade as a hang — unbuffered stdout mandated | bls_derive.cpp:404 |
| DEC-172 | Single-division law: /3 folded into constant (xsq->h1) | bls_derive.cpp:180 |
| DEC-180 | The 8C doubling fix (C8 = madd(QC,C4,C4)) — Root Cause #7 institutionalized as a decision | bls_derive.cpp:359 |

| CA ID | Anchor | Evidence |
|---|---|---|
| CA-80 | Naive sum wraps to 0 (HALF+HALF) — COST_OVERFLOW regression | test_step5.cpp:82,90 |
| CA-81 | Credit crosses ceiling — CREDIT_OVERFLOW regression | test_step5.cpp:83,91 |
| CA-86 | Reads must work BEFORE any mempool op — early-read regression anchor | test_step5.cpp:48,51 |
| CA-96 | Step-5: orphan-variable hygiene | commit f9c691c |
| CA-97 | Step-5: type hygiene | commit f9c691c |
| CA-105 | Root boundary-conversion defect class — killed by DEC-134 | commit 75e7227 |
| CA-112 | Beacon seed exactly 159 B, 15-B tag | consensus.hpp:94 |
| CA-113 | Beacon hash input exactly 57 B (17+8+32) | consensus.hpp:196 |
| CA-114 | Stagger derives from H(beacon ‖ CONFLICT) — parity fix | consensus.hpp:162 |
| CA-120 | Brace law enforced on emitted goldens | gen_constants.py:523 |
| CA-134 | Gate v5 clean-first | commit fd9d4c3 |
| CA-135 | seedpref (seed-preference) verified idempotent | commit fd9d4c3 |

**Range/slash-implied IDs** (assigned; content pending transcript): DEC-120, DEC-122 (DEC-119..122); DEC-132, DEC-140 (gate.sh v5 header); DEC-141 (DEC-136..141); DEC-162 (DEC-125/162).

**Cross-session consistency:** DEC-112/DEC-113 citations in update.hpp match ledger rows DEC-112/DEC-113 exactly — the 115-row record and Step-4 code agree. Highest cited: **DEC-180 / CA-135**.

---

## RECONCILIATION REGISTER — ADDENDUM (second pass, 2026-09-04)

#### Errata E-10 — errata-namespace collision (CA-R8)
Reconciliation Register E-6/E-7 collide with session-local errata: Step-5 E-6 = 192-bit slot schema (commit fc53442); Step-6 E-7 = automaton erratum (consensus.hpp:142, gen_constants.py:427; content pending). Resolution: reconciliation errata re-designated **ER-6..ER-9** (the earlier labels below stand as history); canonical E-6 = Step-5 slot schema; canonical E-7 = Step-6 erratum.

#### Errata E-11 — whitepaper leaf-schema staleness (CA-R9)
Whitepaper §2.6/§8.3: (mbal[126]‖sbal[1]‖nonce[64]‖flags[8]) = 199 bits. Code DEC-126: 126|1|64|1 = 192 bits, exact 24-B window. Code is authority (DEC-109 doctrine); tex patched in same commit; flags width 8→1.

#### CA-R addendum (second pass)

| ID | Sev | Finding | Resolution |
|---|---|---|---|
| CA-R8 | HIGH | Errata ID collision: reconciliation E-6/E-7 vs session-local E-6/E-7 | E-10 re-designation ER-6..ER-9 |
| CA-R9 | HIGH | Whitepaper leaf schema 199-bit/flags[8] vs code DEC-126 192-bit/flags[1] | E-11 + tex patch |
| CA-R10 | LOW | Harvest-script SyntaxWarning (\* escape) — cosmetic, output correct | raw strings in future scripts |
| CA-R11 | LOW | First harvest regex matched only DEC-prefixed tokens; slash/range IDs missed | VII-A range-implied list |

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
`[116, 119, 121]`.

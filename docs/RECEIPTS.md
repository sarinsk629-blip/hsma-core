# HSMA — Wire Receipts (the claims, dated, verifiable)

Every line below appeared in a node log on real hardware. Each has a commit
in this repository that introduced or proves the mechanism behind it.

| # | DATE | RECEIPT (verbatim log line) | WHAT IT PROVES | MECHANISM COMMIT |
|---|---|---|---|---|
| 1 | Oct 12, 07:15:46 UTC | `[pouw-verify] peer epoch 0 weight 262144 CONFIRMED by recomputation` | PoUW weight independently re-derived by a peer node (anchor side) | 37d3ba4 |
| 2 | Oct 12, 08:49:43 UTC | `[pouw-verify] peer epoch 0 weight 262144 CONFIRMED by recomputation` | Second confirmation — different exchange cycle | 37d3ba4 |
| 3 | Oct 12 (fleet) | `[state] epoch 1 digest AGREES (d67b90d5849e6f38)` + `[pouw-verify] peer epoch 1 ... CONFIRMED` | Cross-verification across the epoch-1 boundary, BOTH directions; chain convergence evidenced by matching digest | 37d3ba4 |
| 4 | Oct 12 | 10× `[epoch-pulse] injecting synthetic decree N/10` → `[pi_E] epoch 1 complete` → `wrap_verify ACCEPT` → `[gossip] epoch 1 header sent` | **The first epoch crossing in project history** — the lifecycle executed end-to-end | 90ccb40 |
| 5 | Oct 13 (fleet) | `[work] work_id 1/2/3: VERIFIED (n=256, 4273/4287/4297 ms)` | Three GPU production workloads, 16.7M MACs each, sub-1% variance; ~16× measured speedup over CPU | Phase 6.5 (test_step40 bit-identity) |
| 6 | Oct 13 (fleet) | `[claim] work_id 1 (n=256) folded into the accumulator as a claim-decree` | **The first GPU claim folded into chain state** — cryptographic identity bound into π_E's history | 3429ddf |
| 7 | Oct 12 | `[gate] verify n=64: 615.1 ms ... n=1024: 156835.8 ms` → HOLD | The honest verifier-cost curve — measured, published, architecture rerouted to fold-verification | e46f0a3 |
| 8 | Oct 10–13 | Anchor soak: `NRestarts: 0`, watchdogs 0 in 5+ days (3 fires ALL dated Oct 3–4, pre-timeout-fix), fd-count flat at 9 | The freeze class dead; the fd-leak soak-killer (DEF-302) dead; production stability | DEF-254..263, DEF-302 |
| 9 | Oct 5 | `GATE GREEN — 39/39` on an external contributor's machine (g++-only, no clang) | Portability: the gate self-adapts to the machine's toolchain | DEF-253 |
| 10 | Oct 13 | `[quorum] epoch N: claim-decrees audited (structure+linkage)` — fires at every header exchange | Fleet-side claim auditing, digest-seeded sampling | a34fb30 |
| 11 | Oct 19 (sandbox re-run) | `PREIMAGE byte-exact: a=True b=True \| C recompute=True \| cross=True \| deterministic=True` → `sha256(c)=c187874a447258ff1f925cda72d4d266cd415d6540b3350aee84b14b219ae2a7` | The s1 claim loop re-proven on foreign hardware, bit-identical digest (third independent run: phone, audit box, sandbox) | c134379 |
| 12 | Oct 19 | `claim_inputs/2 (FAUCET) -> 200` + `FAUCET preimage: a==predicted=True b==predicted=True \| C==mod-p recompute=True` → `faucet sha256(c)=007124aec362e8d2a3b560dfecb6c60b5cbd4ac0d3750a41ccb634b0d3dc64b3` | **The faucet 404 is dead**: the node binds its self-generated inputs; the driver independently predicted A/B from the seed law and recomputed C mod p over F_p — preimage served for BOTH mint paths | (this commit) |
| 13 | Oct 19 | `[claim] work_id 3 (n=80) folded` → `[verifier] epoch 1: rotation 1 selected pool[0/1] work 3 — identity PASS \| recompute n/a (above fleet rung) \| CLAIM VERIFIED` + `/verifier {has_receipt:true, pass:true, rotations:1, pool:1}` | **The first live rotation in project history** — the s2 open-item closed via the env-gated testnet CPU band (64<n<=96); the rotating verifier audited a real claim on real hardware — and REJECTED the first one (DEF-374 caught by the tripwire) | (this commit) |
| 14 | Oct 20 | `[rung] n=  64       9 ms … n=256     629 ms … -> IN-RUNG` (tools/rung_probe, the tier-2 call itself) | **The 6.16 gate closes with a receipt**: the tier-2 rung is a MEASURED number (256³ = 16.8M MACs at 629 ms — once-per-pool affordable), not folklore; verifier.hpp's TIER2_RUNG=256 cites this table | (this commit) |
| 15 | Oct 20 | `[shard-6.18] N=1024 … prove 256 blocks: 474099 ms … verify (sampled 16/256): 29577 ms … pass=1 … GREEN` | **6.18 rung-1: 1,024³ block-sharded end-to-end on CPU** — 256 output blocks of 64×64×1024, each a full v2 proof, chain-folded under HSM_SHARD_v1, verified at O(sample) budget; the O(N³)→O(sample) verifier curve is real | (this commit) |
| 16 | Oct 20 | `[verifier-pool] aggregate: 1 claims — tier1 1 ok / 0 bad, tier2 1 ok / 0 bad (0 skipped by budget, 512000 MACs spent) \| POOL CLEAN` + `/verifier … "pool":{"has":true,…,"pass":true}` | **The pool AGGREGATE receipt** — the rotating verifier's audit now covers EVERY claim in the pool (tier-1 all, tier-2 under the measured budget), not one sample | (this commit) |
| 17 | Oct 20 | `[dkg] epoch 1 committee rotated: n=5 t=3 shares_ok=5/5 agg_pk=2f502670cf7c4712…` + `/dkg {has:true, n:5, t:3, shares_verified:5, agg_pk:384-hex}` | **The DKG rotation is WIRED**: the node derives its epoch committee from the chain tip (beacon-seeded Feldman VSS), every share verifies, the aggregate pk moves with the chain — auditable determinism | (this commit) |
| 18 | Oct 20 | `POST /register_model -> 200 {"model_id":4242,"registered":true,"C":1111614908399931266}` + `GET /models -> {"registry_size":1,"models":[{…4242…}]}` | **6.20 live: the registry HOLDS state** — the pre-s4 route printed and forgot (DEF-376 owned); now registration lands in the live Registry, /models publishes it, and submit_gemm admission binds workloads by the opening check | (this commit) |
| 19 | Oct 19 | `test_step54: ALL PASS — 1088 rows EXACT, all SAT, gadget output == fp::poseidon3 (Montgomery-exact), tamper breaks SAT, 3 domains` | **"Poseidon-3 as R1CS" is now semantically TRUE** (DEF-375 fixed): the row count measured at production parameters, the gadget↔permutation bridge finally pinned | 7a56d55 |
| 20 | Oct 20 | `test_step59: ALL PASS — tables certified (exp worst 0 LSB, rsqrt worst 1) \| worst \|P-oracle\|=0.01335 \| row-sum ~128 \| D=1024 boundary ACCEPT, D=1152 REJECT \| both LogUp sides balance, both poisons IMBALANCE` | **6.14 CLOSES: the certified softmax producer** — q7/q14 fixed-point over the exp_shifted + RCP tables, the extended SoftmaxBatch (one trace, two LogUp sides), the exact rung boundary measured | (this commit) |
| 21 | Oct 20 | `test_step60: ALL PASS — full pipeline 11 legs verify \| doctored-P proof REJECTED (the fence holds) \| flipped X REJECTED \| legacy scaffold still verifies` | **The 6.19 fence is SHUT**: P_h is DERIVED by the producer from the proven scores — the attack the rung-1 scaffold could not express now dies in the verifier's own re-derivation | (this commit) |
| 22 | Oct 20 | `test_step61: ALL PASS — rsqrt grid receipt (worst chord 1) \| worst \|y-oracle\|=0.00803 \| n=8 divisions exact \| eps floor rows exact 0 \| negative model rejected \| n-division trace balances` | **6.15 takes the honest rung**: LayerNorm as table+fixup — RCP mean/variance, interpolated rsqrt window, drift pinned at 0.05 (measured 0.00803); exact LayerNorm remains registered circuit work | (this commit) |
| 23 | Oct 20 | `test_step62: ALL PASS — 240x305 shared circuit, 4 real block instances, folded instance SATISFIES \| FS deterministic \| both tamper negatives die \| block C == parent slices \| steps 31/32/33 k=1 regressions GREEN` | **6.18 rung-2: the fold-of-folds through the REAL mfold** — DEF-379 found+fixed on its first k>1 caller; epoch-scale instantiation (10,000³) remains P1-13 | (this commit) |

**The verification commands** (any of these reproduce the evidence):

```bash
# the anchor's live receipts:
ssh <anchor> "sudo journalctl -u hsma-node --no-pager | grep -E 'pouw-verify|claim|quorum' | tail -10"
# the bit-identity gate (any CUDA machine):
./build/test_step40        # PASS: GPU==CPU limb-for-limb; sumcheck ACCEPT (n=128)
# the full gate:
./scripts/gate.sh          # GATE GREEN
```

**Counts at time of writing:** decisions = 68 · owned defects = 80 ·
laws = 280 · conformance programs = 61 —
live counts: `grep -c '^## DEC-' docs/DECISIONS.md`

## P3-PROD — the Zero-MEV pillar's production package (measured at the capstone)

| # | Evidence | Command | Result |
|---|----------|---------|--------|
| P3-P1 | DKG at the capstone: deal + all-224 Feldman verifies | `./build/test_step63` | deal 391 ms; 224 verifies 907 ms — PASS |
| P3-P2 | Second-implementation bit-identity (Python oracle vs C++) | `python3 scripts/gen/steps/step36.py` + `./build/test_step63` | C_k(112) + Y_j(224) + D_j(112) + D_agg + X_E + R — ALL bit-identical |
| P3-P3 | Batch Lagrange vs reference (t=112) | `./scripts/p3_core_check` (or step63 kernel path) | 176.4 ms -> 1.17 ms (150x), bit-identical coefficients |
| P3-P4 | DLEQ share auth at scale | `./build/test_step63` | 112 proves 461 ms (4.1 ms/sh), 112 verifies 140 ms (1.25 ms/sh); forgery + tamper negatives PASS |
| P3-P5 | Checked aggregation + the audit law | `./build/test_step63` | agg 140 ms; e(G1,D_agg)==e(Y1_agg,R) PASS; Y1_agg == [f(0)]G1gen |
| P3-P6 | Envelope roundtrip at scale, carried-hdr law | `./build/test_step63` | cth law + wire decode + stored-hdr decrypt PASS (112-share committee) |
| P3-P7 | 2048-envelope volume + O(1) dedup | `./build/test_step64` | 2048 pushes 1.1 ms (0.5 us/insert); 300-dup replay 0 dup-stores |
| P3-P8 | Ordering ceremony at volume vs reference sort | `./build/test_step64` | 1.9 ms, root == independent reference (2148 entries) |
| P3-P9 | Late-joiner sync: ONE message for the epoch | `./build/test_step64` | 2048 records, 417,796 bytes, roundtrip identity; truncated batch rejected |
| P3-P10 | Multi-region threshold independence | `./build/test_step64` | members 1-112 / 57-168 / 113-224 all decrypt -> same D_agg digest 5b5e8cd3 |
| P3-P11 | Full suite | `ctest` | 41/41 (39 legacy + step63 + step64) |
| P3-P12 | Chain regression tripwire | `git stash; ./scripts/gen_run_new.py; git diff generated/` | steps 7..35 regenerate byte-identical |

**Defects owned this package:** DEF-381 (cth zero-point) · DEF-382 (fixed r=42) · DEF-383 (O(n) dedup) · DEF-384 (3-of-2048 sort fill) · DEF-385 (guessed hdr) · DEF-386 (uninit own share) · DEF-387 (O(t^2) inversions) · DEF-388 (no aggregate verify) — laws CA-R371a..h.

**Counts at time of writing:** conformance programs = 63 ·
live counts: `grep -c '^## ' docs/DECISIONS.md`

## P2 production package (Pillar 2: Consensus) — evidence

| # | Evidence | Command | Result |
|---|----------|---------|--------|
| P2-P1 | Automaton at production params (K=20/40, beta=150, n=224) finalizes | `./build/test_step65` | finalized at exactly round 150 — PASS |
| P2-P2 | DEF-389: order commitment size-exact (pipeline n=1/4/7 vs reference; n=2048 equivariance + tail-binding) | `./build/test_step65` | roots match reference; changed tail cth moves the root — PASS |
| P2-P3 | DEF-392: the u64-overflow catch (agreeing=2^62, sampled=2^63 must be Switched) | `./build/test_step65` | Switched, confidence 0 — PASS |
| P2-P4 | DEF-393: freshness matrix (epoch/root/conflict/round-window, 6 negatives) | `./build/test_step65` | all rejections + in-window acceptance — PASS |
| P2-P5 | DEF-394: vote wire v2 (212B), claimed member verified with ONE pairing; wrong claim rejected; legacy 204B compatible | `./build/test_step65` | 1-pairing accept, wrong-claim reject — PASS |
| P2-P6 | DEF-391: ORDER_SIG 0x0D (140B) — t-th partial attests, foreign root refused, wire tamper detected | `./build/test_step65` | threshold attestation + 3 negatives — PASS |
| P2-P7 | DEF-392b: REAL beacon (deterministic, epoch-bound, not a literal) + REAL breaker (2-candidate resolve, 1-candidate refused) | `./build/test_step65` | 7 checks — PASS |
| P2-P8 | PROPERTY 1 (no front-running): order = pure function of public (beacon, cth); beacon-bound; no plaintext input | `./build/test_step66` | 4/4 PASS |
| P2-P9 | PROPERTY 2 (order-before-knowledge): 6 random (t-1)-subsets TAG-FAIL; t shares decrypt exactly; lock attests at exactly t; forged DLEQ rejected | `./build/test_step66` | 7/7 PASS |
| P2-P10 | PROPERTY 3 (irreversibility): post-decrypt root bit-identical; 8 permutations ALL break root+signature; late envelope excluded; disjoint t-subsets -> same D_agg | `./build/test_step66` | 6/6 PASS |
| P2-P11 | Full suite after the 11-defect fix package | `ctest` | 43/43 (41 legacy + step65 + step66) |
| P2-P12 | Gen-chain regression after DEF-399 (canonical reduction in the order-root lift) | `python3 scripts/gen_run_new.py; git diff generated/` | steps 7..35 regenerate byte-identical (0 insertions/deletions) |
| P2-P13 | Verification gate (clean build + presence asserts + DEC-090 lint + ctest) | `./scripts/gate.sh` | GATE GREEN |

**Defects owned this package:** DEF-389 (4-slot order freeze) · DEF-390 (constant beacon) · DEF-391 (shares pre-lock, unsigned lock) · DEF-392 (u64 quorum math) · DEF-393 (no vote freshness) · DEF-394 (O(n) pairing scan) · DEF-395 (port identity) · DEF-396 (unbounded sampler) · DEF-397 (limiter leak) · DEF-398 (one-shot ceremony) · DEF-399 (non-canonical root lift) — laws CA-R372a..k.

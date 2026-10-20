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
| 14 | Oct 19 | `test_step54: ALL PASS — 1088 rows EXACT, all SAT, gadget output == fp::poseidon3 (Montgomery-exact), tamper breaks SAT, 3 domains` | **"Poseidon-3 as R1CS" is now semantically TRUE** (DEF-375 fixed): the row count measured at production parameters, the gadget↔permutation bridge finally pinned | (this commit) |

**The verification commands** (any of these reproduce the evidence):

```bash
# the anchor's live receipts:
ssh <anchor> "sudo journalctl -u hsma-node --no-pager | grep -E 'pouw-verify|claim|quorum' | tail -10"
# the bit-identity gate (any CUDA machine):
./build/test_step40        # PASS: GPU==CPU limb-for-limb; sumcheck ACCEPT (n=128)
# the full gate:
./scripts/gate.sh          # GATE GREEN
```

**Counts at time of writing:** decisions = 63 · owned defects = 75 ·
laws = 273 · conformance programs = 53 —
live counts: `grep -c '^## DEC-' docs/DECISIONS.md`

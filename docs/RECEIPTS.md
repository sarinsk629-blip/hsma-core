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

**The verification commands** (any of these reproduce the evidence):

```bash
# the anchor's live receipts:
ssh <anchor> "sudo journalctl -u hsma-node --no-pager | grep -E 'pouw-verify|claim|quorum' | tail -10"
# the bit-identity gate (any CUDA machine):
./build/test_step40        # PASS: GPU==CPU limb-for-limb; sumcheck ACCEPT (n=128)
# the full gate:
./scripts/gate.sh          # GATE GREEN
```

**Counts at time of writing:** decisions = 61 · owned defects = 73 ·
laws = 269 · conformance programs = 51 —
live counts: `grep -c '^## DEC-' docs/DECISIONS.md`

# Poseidon in HSMA — the Complete Audit (Phase 6.17 v2 s3)

**Scope**: every Poseidon file in the tree — `poseidon.hpp`, `poseidon_v.hpp`,
`poseidon_r1cs.hpp`, `p1cs.hpp` (→ attic), plus every consumer and every golden.
**Verdict**: Poseidon was always the real hash of the system and fully
INTEGRATED at the arithmetic layer — but the R1CS arithmetization carried a
domain bug (DEF-375) that made "Poseidon as R1CS" a *different function* than
the hash everyone was using, and one abandoned predecessor file (`p1cs.hpp`)
was left broken in-tree. Both are fixed in this phase. Details below.

---

## 1. What Poseidon IS in HSMA (the function)

Poseidon is **the native hash of the chain** — the one hash that is both
efficient to compute AND cheap to prove inside a circuit (x^5 S-box is 3 R1CS
rows; SHA-256 would be ~25,000). HSMA uses a **twin pair** over the Pasta
cycle so that every hash either lives in the base field of a proof system or
in the folding field:

| | **P3 — `poseidon.hpp`** | **VP3 — `poseidon_v.hpp`** |
|---|---|---|
| Field | Pallas F_p (`fp::fe`, 4×u64 Montgomery) | Vesta F_q (`fq::fev`) |
| State | 3 elements | 3 elements |
| S-box | x^5 (x2 → x4 → x·x4) | x^5 |
| Rounds | RF=8 full (4+4), RP=56 partial | 4+4 full, 56 partial |
| Round constants | 80, generated (`poseidon_params_gen.hpp`) | 80, generated (`vesta_poseidon_params_gen.hpp`) |
| Domains (IVs) | 35 pre-minted domain tags (`domain_registry_gen.hpp`): SHA256("HSM_IV_v1\|tag\|nonce") → first canonical field element | 4: CYCLEFOLD (dom=0), STATE_NODE, STATE_LEAF, DECREE |
| API | `poseidon3(dom, l, r)` 2-to-1 hash + `Sponge` (rate-2 duplex, count+one padding) | `poseidon3v(dom, l, r)` + `VestaSponge` |

**Domain separation is structural**: every subsystem hashes under its own
pre-minted IV, so a hash output can never be replayed as a different object
kind (a vote hash is not a tx hash is not a leaf hash — the IV makes the
input spaces disjoint).

## 2. The integration map (who actually consumes Poseidon)

Verified by `grep` over the tree + compile/run receipts — nothing here is
claimed without a consumer or a test:

| Consumer | Uses | Role |
|---|---|---|
| `fold.hpp`, `mfold.hpp`, `nifs.hpp`, `cycfold.hpp` | P3 + VP3 | folding-scheme hashes: accumulator compression, cross-term digest (F_q side = CycleFold) |
| `pcs.hpp`, `sumcheck.hpp` | P3 | commitment/digest derivation in the polynomial layer |
| `smt_r1cs.hpp` | P3 + P3-as-R1CS (via `pr1cs::build`) | the state tree's Merkle openings as constraints |
| `vault.hpp`, `lightclient.hpp`, `g1net.hpp` | P3 | storage integrity, light-client headers, network message digests |
| `sha256.hpp` coexists | — | transport/JSON-layer hashing only (HTTP receipts, wire hex); the chain's *cryptographic* trees and proofs are Poseidon |
| epoch digest chain (`epoch_node.cpp`) | via the fold pipeline | π_E hash history that the s2 verifier and the claim identities bind into |
| PoUW | P3 (domain-separated) | proof digests inside the GEMM proof structure |

**Answer to "is Poseidon integrated?"** — YES at the arithmetic layer, from
day one: 35 goldens (`test_step3`: 35 IVs, 48 permutations, 14 sponge cases),
Vesta-twin goldens (`test_step25`: domain separation, determinism, sponge
round-trip, avalanche), and every folding/PCS/SMT test downstream of it.

## 3. What the audit FOUND (and fixed)

### DEF-375 — the R1CS gadget was not actually computing Poseidon (FIXED)
`pr1cs::mk_fe` stored canonical constant limbs **raw** into a witness system
whose values are **Montgomery** forms (`fe_from_u64`, `iv_of`). The emitted
rows were still SAT — the witness is computed by the same mangled helpers the
rows pin, so the system was self-consistent — but the function it constrained
was NOT `fp::poseidon3`. SAT is representation-blind; no golden ever crossed
the gadget↔permutation boundary, so this survived every prior gate.

**Fix**: `mk_fe` now RR-lifts (canonical → Montgomery) — the gadget is
Montgomery-clean, so every row is the exact F_p semantic it claims
(mont(a)·mont(b)=mont(c) ⟺ a·b=c; the R factors cancel). Callers are
unchanged (they pass canonical arrays; the lift happens at the boundary).

**Proof — `test_step54` (new, 5 properties)**:
- P1: full parameters emit **exactly 1,088 rows** (8×24 + 56×16) — the README
  number, now MEASURED at production parameters, not extrapolated
- P2: all 1,088 rows SAT
- P3: **gadget output == `fp::poseidon3(dom, l, r)`, Montgomery-exact** —
  the bridge that never existed before this phase
- P4: perturbing one intermediate witness breaks SAT (the system is sound)
- P5: the bridge holds across 3 domain IVs with non-trivial inputs

Cross-checks re-run after the fix: `fullposeidon` (1,088 constraints, 0
unsat), `pr1probe` (fixed to the current signature), `smt20probe` (mirror
RR-lifted so `[G-sem]` is now a genuine cross-check — previously it compared
two identical mangles), `smt21probe`, `minitest`, `pie`, `p15eprobe`,
`scaleprobe` — all compile and run GREEN.

### p1cs.hpp — the abandoned predecessor (→ attic)
`p1cs.hpp` was the ORIGINAL P1-14a attempt, abandoned mid-write (DEC-233's
"clean restart" produced `poseidon_r1cs.hpp`). The audit found it left
in-tree with: a dead first pass emitting 3 self-admitted wrong constraints
(`break; // DEBUG: don't generate the full thing yet`), an sbox gadget using
`fe_mul` in violation of its own CA-R158 "plain domain" law, and exactly ONE
caller (the equally-dead `tools/p1probe.cpp`, not a build target). **Moved to
`attic/`** with a banner; no production path ever called it; the build is
unchanged (verified: full rebuild clean).

### Stale documentation (FIXED)
- `poseidon_r1cs.hpp` claimed its goldens came from "step35.py" — that step is
  the stake-golden emitter today. Header rewritten with the real domain law.
- `tools/minitest.cpp` comment pointed at the (now attic) header — updated.

## 4. Verification receipts (this audit, real runs)

```
test_step3  : ALL GREEN (35 IVs, 48 perms, 14 sponge cases)
test_step25 : ALL GREEN (Vesta twin: dom-sep, determinism, sponge, avalanche)
test_step54 : ALL PASS (1088 rows, SAT, == poseidon3, sound, cross-domain)
fullposeidon: 1088 constraints | R1CS SAT: YES (0 unsat out of 1088)
pr1probe    : 80 rows SAT (reduced), real constants
smt20probe  : P1-20 GREEN (SAT + genuine semantic mirror + 4 owned defects re-demonstrated)
test_step20/21/22 : ALL GREEN (PCS/fold/light-client layers downstream of Poseidon)
```

## 5. Open boundary (honest, owned)

`build_smt_opening` v1 carries DEF-192/193/194/195 (dead direction channel,
no root binding, stale n_rows, depth-2 lane collision) — all OWNED defects
with the v2 builder (`build_smt_opening2`) repairing them in-circuit; the
depth-64 production unroll is P1-21 territory (hardware-bound). This audit
verified the artifacts and their defects are exactly as documented — no new
SMT-layer findings beyond DEF-375.

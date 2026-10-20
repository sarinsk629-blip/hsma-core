# THE AI PoUW PILLAR — FINAL PACKAGE (Phase 6.17 v2 s5)

Status: **production-ready at its declared rungs; every claim below has a
receipt; every remaining gap is REGISTERED, not hidden.**
Conformance: 61 programs PASS · GATE617 (build / tests / live / survival) GREEN.
Base commit: fd9e913 + s5. Laws: CA-R370h/i/j/k/l/m/n.

---

## 1. WHAT THE PILLAR CLAIMS (and where the proof lives)

Consensus weight comes from VERIFIED matrix multiplication. The proof chain
is GEMM -> sumcheck -> PCS over the Pallas field, with FS challenges derived
from the prover's own commitments (`pouw.hpp`: prove_gemm_v2 / verify_gemm_v2
— the v2 chain requires no trusted preimage: the verifier re-derives
everything from ITS OWN arrays).

| Component | File | Proof artifact |
|---|---|---|
| The v2 proof chain | pouw.hpp, sumcheck.hpp, pcs.hpp | tests 40/44-class + every leg below |
| The GEMM circuit | gkr.hpp | golden-proven, sumcheck-bound, grind-resistant |
| CPU reference + GPU dispatch | pouw/gemm_backend.hpp | bit-identity gate (test_step40): GPU==CPU limb-for-limb |
| Block-sharded GEMM (6.18) | pouw/block_shard.hpp | 1,024³ on CPU: 256 block proofs, O(sample) verify (RECEIPTS #15); fold-of-folds rung-2 (RECEIPTS #23) |
| Attention (6.19) | pouw/attention.hpp | 8 legs verify (test_step58); the fence CLOSED (test_step60) |
| Softmax producer (6.14) | pouw/softmax.hpp | certified tables + dual LogUp balance (test_step59) |
| LayerNorm (6.15) | pouw/layernorm.hpp | table+fixup rung, drift 0.00803 (test_step61) |
| Model registry (6.20) | pouw/model_commit.hpp | live Registry + admission binding (test_step56, RECEIPTS #18) |
| Measured verifier rung (6.16) | verifier.hpp | 64³=9ms … 256³=629ms table (rung_probe) |
| Pool aggregate verify | verifier.hpp verify_pool() | tier-1 ALL + budgeted tier-2 (RECEIPTS #16) |

## 2. THE FENCE IS CLOSED (the package's headline)

Before s5, attention's P_h (post-softmax weights) was a trusted INPUT — the
honest boundary, in writing, since s4. Now:

1. `pouw/softmax.hpp` produces P_h from the score legs through the
   0-LSB-certified `exp_shifted` table (row-max shift; the exact exp(0)=1
   identity at the boundary; division through the step49 RCP table).
2. The **extended batch type** (the 6.14 roadmap item): `SoftmaxBatch` —
   one softmax's whole lookup trace as TWO LogUp multiset sides (exp + RCP);
   a softmax is certified only when both balance. A fake table value is
   DETECTABLE, not merely wrong.
3. `prove_attention_full` / `verify_attention_full` derive P_h from the
   PROVEN scores; the verifier re-derives it from its own recomputation
   before checking the A legs. The doctored-P attack — unexpressible in the
   old API, demonstrable against the old scaffold — dies here
   (test_step60 P3).

The fixed-point policy, in writing: projection legs prove over the RAW
products (true GEMM statements); the de-scale (>>7, q14->q7) is public
deterministic post-processing on verifier-held arrays; scores are q14,
exactly the producer's domain.

## 3. THE HONEST BOUNDARIES (what is NOT claimed)

- **6.18 headline**: 10,000³ block-sharded is an ARCHITECTURE with proven
  machinery (1,024³ receipt; the fold-of-folds at conformance scale), not a
  completed computation. What remains is GPU-fleet scale and the P1-13
  epoch-scale fold instantiation — scale, not design.
- **6.15 LayerNorm** is the roadmap's REGISTERED approximation: mean and
  variance through RCP (exact for the power-of-two rung n=8), rsqrt through
  an interpolated mantissa window (grid-certified, worst chord error 1).
  Drift vs the real oracle is MEASURED (0.00803) and pinned (0.05).
  Exact LayerNorm in-circuit = registered circuit work.
- **Exact-rung softmax**: D <= 1024 (RCP_MAX) — seq <= 8 for worst-case
  rows; the node's mint rung (n=8) fits exactly. Wider rows are a
  registered scale item, rejected loudly, never silently clamped.
- **Node wiring**: attention/model-admission workloads are library-verified
  end-to-end; the epoch node's HTTP surface exposes mint/verify/claim/
  verifier/dkg/models. Exposing attention proof submission as a route is
  the NEXT wiring step (library-ready, route-pending).

## 4. THE AUDIT THAT ACCOMPANIED THE PACKAGE

The full sweep ran clean at fd9e913 BEFORE any s5 work (61 programs +
GATE617). The audit then found four defects the green gates had licensed:

- **DEF-377** — the committed golden had drifted from its generator (35 vs
  37 IVs). Fixed: the regenerated, determinism-receipted golden is landed
  in this commit. Law CA-R370k.
- **DEF-378** — the A leg proved a DIFFERENT GEMM than it claimed
  (argument-order transposition; prover and verifier shared the misread, so
  it was green). Fixed at all four call sites. Law CA-R370l.
- **DEF-379** — multifold(k>1) dropped the cross-j terms (exact only for
  k=1; every prior caller was k=1). Fixed: sequential application with
  chained cross-terms, challenges unchanged, k=1 bit-compatible (steps
  31/32/33 re-verified). Law CA-R370m.
- **DEF-380** — `x >> 14 + EPS` shifted by 1652 (precedence); caught by
  test_step61's pinned drift on its first run. Fixed + `-Werror=shift-
  count-overflow` is now global. Law CA-R370n.

Three of the four were caught by the NEW machinery this package built. The
package's first customer was the project itself.

## 5. MAINNET-READINESS STATEMENT (the pillar)

Every attention leg is a proven GEMM; the softmax is a certified table with
a balanced batch; LayerNorm is a bounded approximation with a registered
remainder; the sharded headline has its fold machinery; the verifier's rung
is measured, not folklore; the pool audit covers every claim; the registry
holds state and admits workloads by commitment opening. The remaining gap
to mainnet for THIS pillar is operational — GPU-fleet scale, node routes
for attention workloads, and the P1-13 fold instantiation — all registered,
none hidden. The other three pillars (consensus/MSSC, zero-MEV mempool,
holographic state folding) are the next production fronts; their surfaces
ran green in the same 61-program sweep.

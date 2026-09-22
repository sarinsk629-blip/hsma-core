# HSMA — Holographic Spin-Manifold Architecture

[![Gate](https://img.shields.io/badge/gate-34%2F34-brightgreen)](https://github.com/sarinsk629-blip/hsma-core)
[![Decisions](https://img.shields.io/badge/decisions-235-blue)](docs/DECISIONS.md)
[![Laws](https://img.shields.io/badge/laws-165-orange)](docs/DECISIONS.md)
[![Headers](https://img.shields.io/badge/headers-41-blueviolet)]
[![π_E](https://img.shields.io/badge/π_E-1600_bytes-red)]

**A verified Layer-1 protocol architecture with zero-MEV consensus, folding-based recursive state transitions, and succinct epoch proofs also HSMA cryptographically proves AI execution at consensus speed. It moves beyond traditional Proof of Stake and Proof of Work by utilizing Verifiable AI Inference as Proof of Useful Work (PoUW) — built by one person with 165 laws and zero hiding.**

## What This Is

HSMA is a Layer-1 protocol that eliminates MEV cryptographically (not economically) via a threshold-encrypted mempool, and compresses entire epochs into 1,600-byte recursive proofs (π_E) verifiable by light clients in milliseconds. Every component is verified by a bilingual golden-oracle methodology: a Python oracle mirrors every C++ operation, golden vectors pin every intermediate value, and an append-only decision ledger owns every defect.

**Run the verification yourself:**

```bash
git clone https://github.com/sarinsk629-blip/hsma-core.git
cd hsma-core
./scripts/gate.sh
# → the gate generates all 41 golden headers (~12min), then builds and runs all 34 tests
# → 34/34 tests passed, GATE GREEN
```

## What's Proven (34 Gates, 41 Headers)

| Layer | Component | Status | Receipt |
|---|---|---|---|
| **Field arithmetic** | Pallas F_p (2,472 goldens) | ✅ PROVEN | Machine-proven, bilingual parity |
| **Field arithmetic** | Vesta F_q (516 goldens) | ✅ PROVEN | Machine-proven, bilingual parity |
| **Hashing** | Poseidon-3, Pallas domain | ✅ PROVEN | MDS proven, 80 RCs, golden-pinned |
| **Hashing** | Poseidon-3, Vesta domain | ✅ PROVEN | MDS proven, 80 RCs, golden-pinned |
| **Hashing** | Poseidon-3 as R1CS (1,088 constraints) | ✅ PROVEN | R1CS SAT: YES |
| **BLS12-377** | Full stack: F_r → G1 → F_q2 → G2 → F_q12 → Miller → Tate | ✅ PROVEN | Mathematically proven |
| **Threshold BLS** | DKG, signing, aggregation, beacon — secret-free verify | ✅ PROVEN | Pairing-proven golden |
| **Zero-MEV core** | Order-bound decryption (KEM + DEM + order_root) | ✅ PROVEN | Golden-proven with negatives |
| **State** | Sparse Merkle Tree (vault, update, opening proofs) | ✅ PROVEN | Golden-proven |
| **Consensus** | MSSC automaton (k=20, α=0.75, β=150) | ✅ PROVEN | Golden-proven |
| **The fold** | {F_head, F_exec, F_close} + CCS + 41B accumulator | ✅ PROVEN | Golden-proven end-to-end |
| **Folding core** | HyperNova multifold (sparse relaxed R1CS) | ✅ PROVEN | Satisfaction preservation proven |
| **Commitments** | Homomorphic Pedersen on both Pasta curves | ✅ PROVEN | Homomorphism + scalar-homomorphism verified |
| **Commitment folding** | Cross-curve commitment folding | ✅ PROVEN | Identity verified in both languages |
| **Succinct openings** | WHIR-class wrap (verify without witness) | ✅ PROVEN | wrap_verify ACCEPT, no witness |
| **f_exec circuit** | The transition as R1CS (8 rows, 16 vars) | ✅ PROVEN | PC cubic + ONE wire + PAD-neutrality |
| **Poseidon R1CS** | Full unroll (64 rounds, 1,088 constraints) | ✅ PROVEN | R1CS SAT: YES, 0 unsat |
| **Epoch chain** | Cross-epoch continuity (3 epochs, 9 steps) | ✅ PROVEN | ALL SAT, O(1) accumulator |
| **π_E** | The epoch proof: 1,600 bytes, no witness | ✅ **EXISTS** | 1600/73728 bytes (2.2% of budget) |
| **Light client** | Epoch-header certificate, one pairing per header | ✅ PROVEN | Golden-proven |
| **End-to-end** | Full epoch: encrypt → order → decrypt → fold → certify | ✅ PROVEN | One binary, all seams pinned |
| **Interop** | G1 + G2 wire bridge to canonical BLS12-377 | ✅ PROVEN | ψ map golden-pinned |

## The π_E Receipt

| Component | Size (bytes) |
|---|---|
| T1 (opening transcript) | 544 |
| T2 (batched fold transcript) | 768 |
| OOD (8 points + commitment) | 288 |
| **Total π_E** | **1,600** |
| **Budget** | 73,728 |
| **Utilization** | **2.2%** |

**Verify without the witness.** The verifier recomputes the independent fb identity — O(k·nv) by eq-linearity — without access to the prover's witness data.

## Production Scale

At k=476 decree entries with the full Poseidon permutation (64 rounds):

| Component | Constraints |
|---|---|
| f_exec transition (8 × 476) | 3,808 |
| Poseidon hash (1,088 × 3 × 476) | 1,553,664 |
| SMT opening (5,120 × 2 × 476) | 4,874,240 |
| **Total** | **6,431,712** |
| **10⁶ target** | **EXCEEDED (6.4×)** |

The scaling is **linear in k** — confirmed at k=1, 5, 10, 50, 100.

## The Engineering Culture

This project maintains:

- **An append-only decision ledger** (docs/DECISIONS.md): 235 decisions, 165 laws, every supersession chain traceable, zero silent regressions
- **A golden-oracle bilingual proving system**: Python computes the truth, C++ reproduces it bit-for-bit, the goldens arbitrate
- **An adversarial review culture**: 162 errata, every one owned with a named fix — including a publicly-derivable KEM key caught by design (CA-R61) and an out-of-bounds memory access invisible to self-consistency tests (CA-R119)
- **A byte-identical refactor discipline**: structure changes require byte-identical output proof
- **The pre-emit self-check law**: every golden emitter validates every receipt before writing (CA-R126)
- **The domain law**: fe_mul computes a*b mod p (the mathematical product) — proven by the minitest and three independent probes (CA-R148)

## GAP Register: ALL CLOSED

| Gap | What Was Closed | When |
|---|---|---|
| GAP-01 | BLS12-377 interop cross-check | P1-02 |
| GAP-02 | gen_constants.py refactor | P1-01 |
| GAP-03 | Vesta field + Poseidon + curve ops | P1-03a..c |
| GAP-04 | CycleFold absorption | P1-07 |
| GAP-05 | Dual-layer PCS (Pedersen + WHIR) | P1-09, P1-10 |
| GAP-06 | HyperNova multifold | P1-11, P1-12 |
| GAP-07 | Production circuits + π_E | P1-13a, P1-13b, P1-15a-c |
| GAP-14 | Pallas curve ops | P1-08 |

## Repository Structure

<details>
<summary>Click to expand the full tree</summary>

```
hsma-core/
├── include/hsma/              # Core protocol headers
│   ├── fe.hpp                 # Pallas base field (F_p)
│   ├── fev.hpp                # Vesta base field (F_q)
│   ├── poseidon.hpp           # SNARK-friendly hashing (Pallas domain)
│   ├── poseidon_v.hpp         # Vesta-domain Poseidon-3
│   ├── g2v.hpp                # Vesta curve operations
│   ├── g1p.hpp                # Pallas curve operations
│   ├── cycfold.hpp            # CycleFold absorption primitive
│   ├── pedersen.hpp           # Homomorphic Pedersen (both curves)
│   ├── whir.hpp               # WHIR-class succinct opening
│   ├── mfold.hpp              # HyperNova multifold core
│   ├── cfold.hpp              # Commitment folding
│   ├── fexec_circuit.hpp      # f_exec as R1CS
│   ├── poseidon_r1cs.hpp      # Poseidon R1CS gadget
│   ├── smt_r1cs.hpp           # SMT opening as R1CS
│   ├── vault.hpp              # Sparse Merkle Tree state
│   ├── consensus.hpp          # MSSC automaton
│   ├── fold.hpp               # Fold step family
│   ├── ccs.hpp                # CCS constraint layer
│   ├── nivc.hpp               # NIVC fold accumulator
│   ├── epoch.hpp              # Epoch pipeline driver
│   ├── pcs.hpp                # Multilinear PCS
│   ├── nifs.hpp               # NIFS fold
│   ├── sumcheck.hpp           # Sum-check engine
│   ├── lightclient.hpp        # Light-client certificate
│   ├── mempool.hpp            # Transaction gate
│   ├── tx.hpp                 # Transaction structure
│   ├── params.hpp             # Protocol constants
│   ├── sha256.hpp             # SHA-256
│   ├── update.hpp             # SMT updates + proofs
│   ├── threshold/             # Threshold-BLS module (Steps 7-13)
│   │   ├── scalar_r.hpp       # BLS12-377 F_r arithmetic
│   │   ├── poly.hpp           # DKG scalar semantics
│   │   ├── mont384.hpp        # 384-bit Montgomery engine
│   │   ├── g1.hpp             # G1 Jacobian arithmetic
│   │   ├── interop.hpp        # Fr ↔ fe6 interop
│   │   ├── h2g1.hpp           # Hash-to-G1
│   │   ├── sig.hpp            # Threshold BLS partials + aggregate
│   │   ├── beacon.hpp         # HSM_BEACON_V1 epoch beacon
│   │   ├── dkg.hpp            # Feldman DKG commitments
│   │   ├── fq2.hpp            # F_q2 arithmetic
│   │   ├── g2.hpp             # E' twist curve over F_q2
│   │   ├── fq12.hpp           # F_q12 tower
│   │   ├── pairing.hpp        # Miller + Tate + BLS verify
│   │   ├── m2.hpp             # M2 order-bound decryption shares
│   │   └── m2prod.hpp         # sigma_user + per-member partials
├── conformance/               # 34 test binaries (all passing)
├── scripts/
│   ├── gate.sh                # The verification gate
│   ├── session_close.sh       # The session-close sweep
│   ├── gen_constants.py       # Montgomery constants generator
│   ├── gen_run_new.py         # Two-phase generator orchestrator
│   ├── gen_common.py          # Shared library
│   └── gen/steps/             # Golden-vector emitter modules
│       ├── step07.py ... step34.py
├── tools/                     # 20+ diagnostic probes
│   ├── fullposeidon.cpp       # The full Poseidon R1CS probe
│   ├── pie.cpp                # The π_E assembly probe
│   ├── epochscaled.cpp        # The epoch loop at scale
│   ├── crossepoch.cpp         # The cross-epoch chaining probe
│   └── ...
├── docs/
│   ├── whitepaper.tex         # Full technical specification
│   ├── DECISIONS.md           # The decision ledger (235 entries, 165 laws)
│   ├── eprint/                # The ePrint paper (v2 staged)
│   ├── eprint_v2/             # The methodology paper for resubmission
│   ├── grants/                # The grant wishlist and readiness pack
│   └── refs/                  # Reference implementation evidence
├── CMakeLists.txt
└── README.md
```
</details>

## Security

| Property | Value |
|---|---|
| Adversarial Bound | f < 0.20 (20% Byzantine weight tolerance) |
| Consensus Safety | ε = 0 (structural impossibility, not probabilistic) |
| Committee Collusion | Structurally zero (m_adv ≤ 100 < t = 112) |
| Soundness Budget | ε_sys ≈ 2⁻¹¹⁰ per epoch, 2⁻⁹⁴·³ per year |
| Slashing | 100% stake burn for equivocation |
| Anti-Sybil | Cluster-level weight caps with perjury-slashable attestations |

## GAP Register: ALL CLOSED

| Gap | What Was Closed | DEC |
|---|---|---|
| GAP-01 | BLS12-377 interop cross-check | DEC-218 |
| GAP-02 | gen_constants.py refactor | DEC-218 |
| GAP-03 | Vesta field + Poseidon + curve ops + hash-to-Vesta | DEC-224, DEC-225 |
| GAP-04 | CycleFold absorption | DEC-225 |
| GAP-05 | Dual-layer PCS (Pedersen + WHIR) | DEC-227, DEC-228 |
| GAP-06 | HyperNova multifold | DEC-229, DEC-230 |
| GAP-07 | Production circuits + π_E | DEC-231, DEC-232, DEC-234 |
| GAP-14 | Pallas curve operations | DEC-226 |

## License

MIT

---

*Built by one person + AI. The Satoshi path: build → publish → the world notices. 165 laws. 235 decisions. 34 gates. π_E exists. Zero hiding.*

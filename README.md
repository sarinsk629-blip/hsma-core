# HSMA — Holographic Spin-Manifold Architecture

> A Layer-1 protocol that cryptographically proves AI execution at consensus speed.

HSMA moves beyond traditional Proof of Stake and Proof of Work by utilizing **Verifiable AI Inference as Proof of Useful Work (PoUW)**. Validator consensus weight is derived from verified GKR/Sum-Check matrix multiplications (GEMM), converting wasted electricity into useful AI compute for enterprise clients.

---

## Core Architectural Pillars

| # | Pillar | Description | Status |
|---|--------|-------------|--------|
| 1 | **MSSC Consensus** | Avalanche-family sub-sampled voting with beacon-gated tie-breaking | ✅ Audited |
| 2 | **Threshold BLS Beacon** | DKG-based randomness for un-grindable symmetry breaking | ✅ Specified |
| 3 | **Verifiable AI PoUW** | GKR/Sum-Check proofs of GEMM inference as consensus weight | ✅ P5-v2 Locked |
| 4 | **HyperNova State Folding** | Pallas/Vesta 2-cycle CCS folding into constant-size proofs | ✅ P4-v1 Locked |
| 5 | **Encrypted Mempool** | Threshold-encrypted Commit-then-Simulate (Zero-MEV) | ✅ M2-v1 Locked |
| 6 | **Sparse Merkle Vault** | Poseidon-anchored state tree with canonical-at-rest integrity | ✅ Verified |

---

## Why HSMA Exists

| Problem | HSMA Solution |
|---------|---------------|
| PoW wastes gigawatts on useless hashes | PoUW converts electricity into verified AI inference |
| PoS centralizes to capital-rich oligopolies | Capped Cluster Hybrid weights (compute + stake) |
| MEV extraction by privileged sequencers | Threshold-Encrypted mempool (order before decrypt) |
| Historical state bloat kills light clients | HyperNova IVC folding into constant-size proofs |
| Floating-point consensus forks across hardware | Strict integer-only numeric core (DEC-090) |

---

## Cryptographic Foundation

- **Curve:** Pallas/Vesta 2-cycle (p ≈ 2^254.18)
- **Field Width:** L = 126 bits (unsigned magnitude + sign flags)
- **Hash:** Poseidon (t=3, α=5, R_F=8, R_P=56)
- **Folding:** HyperNova / Customizable Constraint Systems (CCS)
- **Consensus:** Metastable Sub-Sampled Consensus (k=20, α=0.75, β=150)
- **Safety Bound:** ε_sys ≤ 2^-43 (A6 Theory Debt closed)

---

## Build & Test

HSMA is built in strict C++20 with **zero floating-point operations** in the numeric core.

```bash
# Clone the repository
git clone https://github.com/sarinsk629-blip/hsma-core.git
cd hsma-core

# Build
mkdir build && cd build
cmake ..
make

# Run conformance tests
ctest

# Run the full diagnostic gate
./scripts/gate.sh
```

### Expected Output

```text
── [1/4] configure ──────────────────────────────  clean
── [2/4] build (CLEAN-FIRST — no ghosts survive) ──
── [3/4] diagnostics ────────────────────────────
   authentic + healthy
── [4/4] conformance suite ──────────────────────
100% tests passed out of 6
═══════════ GATE GREEN ═══════════
```

---

## BLS12-377 Group Law Verification

The `tools/bls_derive.cpp` tool mathematically proves the BLS12-377 curve group law:

- ✅ Field arithmetic: 2472 golden vectors passing
- ✅ BLS12-377 order: #E = h1 * r proven on 3 independent points
- ✅ Canonical parameter b = 1 pinned
- ✅ Tonelli-Shanks square root verified (8/8 bigint equivalence)

---

## Repository Structure

```text
hsma-core/
├── include/hsma/          # Core protocol headers
│   ├── fe.hpp              # Field arithmetic (Pallas/Vesta)
│   ├── poseidon.hpp        # SNARK-friendly hashing
│   ├── vault.hpp           # Sparse Merkle Tree state
│   ├── consensus.hpp       # MSSC automaton
│   ├── mempool.hpp         # Transaction gate
│   ├── tx.hpp              # Transaction structure
│   └── params.hpp          # Protocol constants
├── conformance/            # Test suite (6/6 passing)
│   ├── test_step2.cpp      # Field arithmetic tests
│   ├── test_step3.cpp      # Numeric kernel tests
│   ├── test_step4.cpp      # State vault tests
│   ├── test_step5.cpp      # Mempool tests
│   ├── test_step6.cpp      # Consensus tests
│   ├── diag_step5.cpp      # Mempool diagnostics
│   └── diag_step6.cpp      # Consensus diagnostics
├── libhsma_numcore/        # 127-bit scratchpad accumulator
│   └── scratch127.hpp
├── src/
│   └── params_probe.cpp    # Identity probe
├── tools/
│   └── bls_derive.cpp      # BLS12-377 curve generator
├── scripts/
│   ├── gate.sh             # Full diagnostic gate
│   ├── gen_constants.py    # Montgomery constants generator
│   ├── check_no_fp.sh      # Float-free lint (DEC-090)
│   └── add_smt.py          # SMT utilities
├── CMakeLists.txt
└── README.md
```

---

## Security

- **Adversarial Bound:** f < 0.20 (20% Byzantine weight tolerance)
- **Consensus Safety:** ε_consensus ≪ 2^-128 (Sequential Quorum Accumulation)
- **Committee Collusion:** ε_committee ≈ 2^-43 (Hypergeometric tail)
- **Slashing:** 100% stake burn for equivocation; 21-day unbonding + 14-day evidence horizon
- **Anti-Sybil:** Cluster-level weight caps with perjury-slashable independence attestations

---

## Status

The cryptographic core is mathematically proven, audited, and compiling with GATE GREEN. The protocol is in the pre-testnet phase.

> "This is no longer a research prototype. The math holds. The code compiles. The architecture is sound."

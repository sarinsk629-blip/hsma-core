# HSMA: Holographic Spin-Manifold Architecture

**A Layer-1 protocol that cryptographically proves AI execution at consensus speed — with Zero-MEV, structural zero security, and recursive state folding into a 41-byte accumulator.**

[![Gate](https://img.shields.io/badge/Gate-GREEN_25%2F25-brightgreen)]()
[![Tests](https://img.shields.io/badge/Tests-25%2F25_passing-brightgreen)]()
[![Decisions](https://img.shields.io/badge/Ledger-223_decisions-blue)]()
[![Errata](https://img.shields.io/badge/Errata-114_owned_closed-orange)]()
[![Phase](https://img.shields.io/badge/Phase-0_COMPLETE_|_Phase_1_IN_PROGRESS-yellow)]()

## Core Architectural Pillars

| # | Pillar | Description | Status |
|---|--------|-------------|--------|
| 1 | MSSC Consensus | Avalanche-family sub-sampled voting with beacon-gated tie-breaking | ✅ Proven (Steps 1–6) |
| 2 | Threshold BLS Beacon | DKG-based randomness, secret-free verify, HSM_BEACON_V1 | ✅ Proven (Steps 7–9) |
| 3 | Verifiable AI PoUW | GKR/Sum-Check proofs of GEMM inference as consensus weight | ✅ Engine proven (Steps 19–20) |
| 4 | HyperNova State Folding | Pallas/Vesta 2-cycle CCS folding into constant-size proofs | ✅ Phase-0 proven (Steps 14–17, 21) |
| 5 | Encrypted Mempool (M2) | Threshold-encrypted Commit-then-Simulate (Zero-MEV) | ✅ Production-hardened (Steps 12–13) |
| 6 | Sparse Merkle Vault | Poseidon-anchored state tree, canonical-at-rest | ✅ Proven (Step 4) |
| 7 | Light-Client Certificate | One pairing per epoch header | ✅ Proven (Step 22) |
| 8 | Interop Bridge | Wire map to canonical BLS12-377 (G1 + G2) | ✅ Golden-pinned (P1-02) |

## Why HSMA Exists

| Problem | HSMA Solution |
|---------|---------------|
| PoW wastes gigawatts on useless hashes | PoUW converts electricity into verified AI inference |
| PoS centralizes to capital-rich oligopolies | Capped Cluster Hybrid weights (compute + stake) |
| MEV extraction by privileged sequencers | Threshold-encrypted mempool (order before decrypt) |
| Historical state bloat kills light clients | HyperNova IVC folding into constant-size proofs |
| Floating-point consensus forks across hardware | Strict integer-only numeric core (DEC-090) |

## The Numbers

```
25/25 conformance tests passing (GATE GREEN)
223 decisions in the append-only ledger (zero silent regressions)
114 errata — every one owned, named, and closed
32 machine-generated headers, verified per gate run
1 committee testifying across 5 cryptographic pillars
1 end-to-end epoch binary running the full pipeline in 21 seconds
1 interop bridge to canonical BLS12-377 (psi wire map, golden-pinned)
```

## The Architecture (One Line)

> **Ordering separated from knowledge (structural), safety separated from statistics (zeros, not probabilities), history separated from verification (one 73 KB proof), security priced in burned capital rather than probabilistic goodwill.**

## Key Innovations

1. **Order-Before-Knowledge (INV-M2-1):** No committee member can learn transaction contents before the execution position is irreversibly committed — enforced structurally, not by punishment.
2. **Structural Zero Security:** Under adversarial weight f < 0.20, authenticated quorum forgery is **impossible** (ε = 0), not merely improbable.
3. **The 41-Byte Accumulator:** The NIVC fold accumulator is CONSTANT size regardless of transaction count — the succinctness mechanism that makes π_E O(1).
4. **The Cross-Pillar Golden Linkage:** One G7 committee testifies across DKG (step 7), threshold signing (step 9), the pairing (step 10), consensus (step 11), the M2 core (step 12), the fold (steps 14–17), and the light-client certificate (step 22).
5. **The Bilingual Golden-Oracle Methodology:** Python computes the truth, C++ reproduces it bit-for-bit, the goldens arbitrate — 113 defects caught by this system, including a publicly-derivable KEM key.

## Quick Start

```bash
git clone https://github.com/sarinsk629-blip/hsma-core.git
cd hsma-core
mkdir build && cd build
cmake .. && cmake --build .
ctest --test-dir build
# ═══ GATE GREEN ═══
```

## Cryptographic Foundation

| Component | Spec |
|-----------|------|
| Curves | Pallas/Vesta 2-cycle (p ≈ 2^254.18) + BLS12-377 (pairing-friendly) |
| Field Width | L = 126 bits (unsigned magnitude + sign flags, canonical signed encoding) |
| Hash | Poseidon-3 (t=3, α=5, R_F=8, R_P=56) — Pallas + Vesta domains |
| Folding | HyperNova / Customizable Constraint Systems (CCS) over the Pasta cycle |
| Consensus | Metastable Sub-Sampled Consensus (k=20, α=0.75, β=150) |
| Signatures | BLS12-377 threshold-BLS with secret-free pairing verification |

## What's Proven (Phase 0 + Phase 1 Progress)

| Layer | What | Proof |
|-------|------|-------|
| Field arithmetic | Pallas (2,472 goldens) + Vesta (516 goldens) | Machine-proven |
| Hashing | Poseidon-3 (Pallas + Vesta domains) | MDS proven, 80 RCs each |
| BLS12-377 | Full stack: F_r → G1 → F_q2 → G2 → F_q12 → Miller → Tate | Mathematically proven |
| Threshold BLS | DKG, signing, aggregation, beacon — secret-free verify | Pairing-proven golden |
| Zero-MEV core | Order-bound decryption (KEM + DEM + order_root) | Golden-proven with negatives |
| The fold | {F_head, F_exec, F_close}, CCS constraints, 41B accumulator, epoch pipeline | Golden-proven end-to-end |
| Transport | Beacon-seeded sampler, 4-tier taxonomy, contact root, EMA | Golden-proven |
| Proof machinery | Sum-check engine, commitment layer, NIFS fold | Golden-proven |
| Light client | Epoch-header certificate, one pairing per header | Golden-proven |
| End-to-end | Full epoch: encrypt → order → decrypt → fold → certify | One binary, 21 seconds |
| Interop | G1 + G2 wire bridge to canonical BLS12-377 | ψ map golden-pinned |

## What's Not Built Yet (Honest)

| Gap | Status |
|-----|--------|
| Real π_E generation (HyperNova multifold with homomorphic PCS) | Specified, in progress |
| Full CycleFold curve operations | Field + Poseidon proven; curve ops next |
| Production transport (sockets) | Crypto layer proven; adapter needed |
| External security audit | The self-audit caught 114 bugs; an independent firm is needed |
| Testnet | Phase 2 |

## Security

| Property | Value |
|----------|-------|
| Adversarial Bound | f < 0.20 (20% Byzantine weight tolerance) |
| Consensus Safety | ε = 0 (structural impossibility, not probabilistic) |
| Committee Collusion | Structurally zero (m_adv ≤ 100 < t = 112) |
| Soundness Budget | ε_sys ≈ 2^-110 per epoch, 2^-94.3 per year |
| Slashing | 100% stake burn for equivocation |
| Anti-Sybil | Cluster-level weight caps with perjury-slashable attestations |

## The Engineering Culture

This project maintains:
- An **append-only decision ledger** ([docs/DECISIONS.md](docs/DECISIONS.md)): 223 decisions, every supersession chain traceable, zero silent regressions
- A **golden-oracle bilingual proving system**: Python computes the truth, C++ reproduces it bit-for-bit, the goldens arbitrate
- An **adversarial review culture**: 114 errata, every one owned with a named fix — including a publicly-derivable KEM key caught by design
- A **byte-identical refactor discipline**: structure changes require byte-identical output proof

## Repository Structure

<details>
<summary>Click to expand the full tree</summary>

```
hsma-core/
├── include/hsma/              # Core protocol headers
│   ├── fe.hpp                 # Pallas base field (F_p)
│   ├── fev.hpp                # Vesta base field (F_q) — GAP-03a
│   ├── poseidon.hpp           # SNARK-friendly hashing (Pallas domain)
│   ├── poseidon_v.hpp         # Vesta-domain Poseidon-3 — GAP-03b
│   ├── vault.hpp              # Sparse Merkle Tree state
│   ├── consensus.hpp          # MSSC automaton
│   ├── fold.hpp               # Fold step family {F_head, F_exec, F_close}
│   ├── ccs.hpp                # CCS constraint layer
│   ├── nivc.hpp               # NIVC fold accumulator, 41B bounded
│   ├── epoch.hpp              # Epoch pipeline driver
│   ├── g1net.hpp              # G1 transport skeleton
│   ├── sumcheck.hpp           # Sum-check engine
│   ├── pcs.hpp                # Phase-0 multilinear PCS
│   ├── nifs.hpp               # NIFS fold
│   ├── lightclient.hpp        # Light-client epoch-header certificate
│   ├── mempool.hpp            # Transaction gate
│   ├── tx.hpp                 # Transaction structure
│   ├── params.hpp             # Protocol constants (static_assert enforced)
│   ├── sha256.hpp             # FIPS-180 SHA-256
│   ├── update.hpp             # SMT updates + proofs
│   └── threshold/             # Pillar-II threshold module (Steps 7-13)
│       ├── scalar_r.hpp       # BLS12-377 F_r Montgomery CIOS kernel
│       ├── poly.hpp           # DKG scalar semantics
│       ├── mont384.hpp        # 384-bit Montgomery engine
│       ├── g1.hpp             # G1 Jacobian arithmetic
│       ├── interop.hpp        # Fr ↔ fe6 interop
│       ├── h2g1.hpp           # Hash-to-G1
│       ├── sig.hpp            # Threshold BLS partials + aggregate
│       ├── beacon.hpp         # HSM_BEACON_V1 epoch beacon
│       ├── dkg.hpp            # Feldman DKG commitments
│       ├── fq2.hpp            # F_q2 arithmetic
│       ├── g2.hpp             # E' twist curve over F_q2
│       ├── fq12.hpp           # F_q12 tower
│       ├── pairing.hpp        # Miller + Tate + BLS verify
│       ├── m2.hpp             # M2 order-bound decryption shares
│       └── m2prod.hpp         # sigma_user + per-member partials
├── conformance/               # Test suite (25/25 passing)
│   ├── test_step2..25.cpp     # 25 conformance binaries
│   ├── diag_step5.cpp         # Mempool diagnostics
│   └── diag_step6.cpp         # Consensus diagnostics
├── scripts/
│   ├── gate.sh                # Full diagnostic gate
│   ├── gen_constants.py       # Montgomery constants generator (frozen)
│   ├── gen/                   # Refactored generator package
│   ├── gen_common.py          # Shared Phase-1 library
│   ├── gen_run_new.py         # New-path orchestrator
│   └── check_no_fp.sh         # Float-free lint (DEC-090)
├── tools/
│   └── bls_derive.cpp         # BLS12-377 curve generator
├── docs/
│   ├── whitepaper.tex         # Full technical specification
│   ├── DECISIONS.md           # Decision ledger (223 entries)
│   └── refs/                  # Reference implementation evidence
├── CMakeLists.txt
└── README.md                  # This file
```

</details>

## License

MIT

---

*Built by one person + AI. The Satoshi path: build → publish → the world notices.*

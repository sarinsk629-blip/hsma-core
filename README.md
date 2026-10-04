<div align="center">

# 🧬 HSMA — Holographic Spin-Manifold Architecture

### *Not a blockchain. Not a DAG. A new category of protocol.*

[![HSMA Gate](https://github.com/sarinsk629-blip/hsma-core/actions/workflows/gate.yml/badge.svg)](https://github.com/sarinsk629-blip/hsma-core/actions/workflows/gate.yml)
[![Gate](https://img.shields.io/badge/gate-34%2F34_GREEN-brightgreen?style=for-the-badge)](https://github.com/sarinsk629-blip/hsma-core)
[![Decisions](https://img.shields.io/badge/decisions-281-blue?style=for-the-badge)](docs/DECISIONS.md)
[![Defects Owned](https://img.shields.io/badge/defects_owned-223-red?style=for-the-badge)](docs/DECISIONS.md)
[![Laws](https://img.shields.io/badge/laws-203-orange?style=for-the-badge)](docs/DECISIONS.md)
[![Headers](https://img.shields.io/badge/headers-41-blueviolet?style=for-the-badge)]
[![π_E](https://img.shields.io/badge/π_E-1600_bytes-critical?style=for-the-badge)]
[![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)]

**A verified Layer-1 protocol where consensus weight derives from verified AI inference,
the mempool is cryptographically unreadable before ordering,
and entire epochs compress into 1,600-byte recursive proofs.**

**Built by one person. 223 defects owned. Zero hiding.**

[📄 Whitepaper PDF](https://github.com/sarinsk629-blip/hsma-core/releases/download/v4.0-whitepaper/Whitepaper_HSMA___Core_Ultimate.pdf) •
[📝 LaTeX Source](docs/whitepaper_v4.tex) •
[📊 Decision Ledger](docs/DECISIONS.md) •
[🌐 Landing Page](https://sarinsk629-blip.github.io/hsma-core/) •
[🟢 Live Explorer](http://3.237.91.235:32233)


## 🤝 Join the Community

[![Telegram](https://img.shields.io/badge/Telegram-Group-26A5E4?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/hsmaCoreFounder)
[![Channel](https://img.shields.io/badge/Telegram-Channel-26A5E4?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/hsmaFounder)
[![Discord](https://img.shields.io/badge/Discord-Server-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/sWE3BfZ9P)
[![WhatsApp](https://img.shields.io/badge/WhatsApp-Group-25D366?style=for-the-badge&logo=whatsapp&logoColor=white)](https://chat.whatsapp.com/JvUFmzMJzFo6BV5xH2JqXw?s=cl&p=a&mlu=4&ilr=4)
[![X](https://img.shields.io/badge/Twitter%2FX-%40hsmaFounder-000000?style=for-the-badge&logo=x&logoColor=white)](https://x.com/hsmaFounder)

</div>

### 📲 Connect to the public seed node (running 24/7 on AWS us-east-1):
 git clone https://github.com/sarinsk629-blip/hsma-core.git
    cd hsma-core
    
    cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build --parallel 1
    
    ./scripts/gate.sh                → GATE GREEN (39/39)

    # Start your node and join the network:
    ./build/epoch_node 31234 --seed 3.237.91.235:31233

#### then watch the live peers counter: 
http://3.237.91.235:32233/api
No token. No sale. No premine. Economics will be designed with contributors, not for them.
223 defects owned publicly — every one with evidence, fix, and a generalizable law. Zero hiding.
If the gate runs GREEN on your machine, star the repo — that is how independent research gets seen.

## ⚡ Run The Verification Yourself

```bash
git clone https://github.com/sarinsk629-blip/hsma-core.git
cd hsma-core
./scripts/gate.sh
```

```
→ 41 golden headers generated (determinism-proven: two-run byte-identical)
→ 34/34 conformance tests passed
→ GATE GREEN
```

> No external dependencies. No libraries. No trust required.
> Every constant is mechanically derived. Every defect is owned.
> **The verification is reproducible by anyone, on any hardware.**

---

## 🏛️ The Four Pillars

<table>
<tr>
<td width="50%" valign="top">

### 🔬 Pillar 1: Verifiable AI Inference (PoUW)

**Consensus weight derives from verified matrix multiplications** — not wasted energy, not capital.

```
128³ GEMM = 2,097,152 MACs
verifies in ~1,216 bytes
O(log N) verifier work
```

- Whole-GEMM sum-check reduction (Theorem-proven)
- Aggregate verify: **3.0× speedup** (= N, scales to 224×)
- External submission mode with Pedersen binding
- The grinding cost: ~2²⁵³

</td>
<td width="50%" valign="top">

### 🗳️ Pillar 2: Metastable Sub-Sampled Consensus

**Weight-proportional sampling with structural quorum impossibility.**

```
α = 0.75 quorum threshold
ε_quorum = 0 (impossible, not improbable)
Beacon-gated deadlock resolution
Convergence demonstrated: 6 rounds
```

- Avalanche-family, weight-proportional sampling
- The flip mechanism: demonstrated (B → A)
- 50/50 deadlock → beacon resolves deterministically
- Aggregate verify: 3.0× speedup measured

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🔒 Pillar 3: Zero-MEV Encrypted Mempool

**Nobody can front-run what nobody can read.**

```
Commit-then-Simulate ceremony
Threshold-encrypted (t = 112 of n = 224)
Ordering committed BEFORE decryption
ε_MEV = 0 (structural, not economic)
```

- 10 encrypted envelopes → ordered → decrypted → folded
- The DEM tag catches tampered ciphertexts
- Non-members cannot decrypt (proven)
- 1 member alone cannot decrypt (proven)

</td>
<td width="50%" valign="top">

### 📐 Pillar 4: Holographic State Folding

**The entire epoch history compresses into 1,600 bytes.**

```
41-byte accumulator (O(1) in tx count)
π_E = 1,600 bytes (2.2% of budget)
verifiable WITHOUT the witness
118 ms on ARM64 (phone-class)
```

- HyperNova NIVC over the Pasta 2-cycle
- The 41-byte accumulator: O(1) in entries
- Cross-epoch chaining: 3 epochs, 9 steps, ALL SAT
- Light client: one pairing per header

</td>
</tr>
</table>

---

## 📊 The Capstone Receipt — All Four Pillars in One Run

```
┌─────────────────────────────────────────────────────────────────┐
│          THE COMPLETE COMMIT-THEN-SIMULATE PIPELINE             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  10 ENCRYPTED envelopes arrive (nobody can read them)           │
│  → ORDER COMMITTED (root=7ec2cd4c..., beacon-shuffled)          │
│    (the ordering is irreversible BEFORE any decryption exists)  │
│  → 10 THRESHOLD DECRYPTS (all tag OK)                           │
│     [decrypt] envelope 0: "encrypted-decree-0" (tag OK)         │
│     [decrypt] envelope 1: "encrypted-decree-1" (tag OK)         │
│     ... through envelope 9 ...                                  │
│  → 10 FOLDS (ALL SAT)                                           │
│     [fold] decree 1/10 folded, SAT                              │
│     [fold] decree 2/10 folded, SAT                              │
│     ... through decree 10/10 ...                                │
│  → π_E epoch 1: wrap_verify ACCEPT (stage=0)                    │
│  → PoUW epoch 1: 64³ GEMM ACCEPT, weight 262,144 MACs, 1185 ms  │
│                                                                 │
│  ALL FOUR PILLARS. ONE SYSTEM. ONE RECEIPT.                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📊 What's Proven — 34 Gates, 41 Headers

<details>
<summary><b>🔬 Click to expand the complete verification table (22 modules)</b></summary>

| # | Layer | Component | Status | Receipt |
|:---:|---|---|:---:|---|
| 1 | Field | Pallas F_p (2,472 goldens) | ✅ | Bilingual parity |
| 2 | Field | Vesta F_q (516 goldens) | ✅ | Bilingual parity |
| 3 | Hash | Poseidon-3, Pallas domain | ✅ | MDS proven, 80 RCs |
| 4 | Hash | Poseidon-3, Vesta domain | ✅ | MDS proven, 80 RCs |
| 5 | Hash | Poseidon-3 as R1CS (1,088 constraints) | ✅ | R1CS SAT: YES |
| 6 | BLS12-377 | F_r Montgomery CIOS kernel | ✅ | 64 DRBG pairs bit-exact |
| 7 | BLS12-377 | G1 Jacobian arithmetic | ✅ | 48 golden triples |
| 8 | BLS12-377 | Hash-to-G1 + Feldman DKG | ✅ | 34/34 share equations |
| 9 | BLS12-377 | Threshold BLS + beacon | ✅ | Real beacon chain |
| 10 | BLS12-377 | F_q2 + E' twist + G2 | ✅ | Generator-discovered |
| 11 | BLS12-377 | Pairing (Miller + Tate + BLS law) | ✅ | Secret-free verify |
| 12 | Zero-MEV | Order-bound decryption shares | ✅ | With 3 negatives |
| 13 | Zero-MEV | σ_user authorization + replay rejection | ✅ | Production hardened |
| 14 | Folding | Fold step family {F_head, F_exec, F_close} | ✅ | Golden-proven |
| 15 | Folding | CCS constraint layer + PC-matrix SAT | ✅ | All illegal edges unsat |
| 16 | Folding | 41-byte NIVC accumulator | ✅ | O(1) in entries |
| 17 | Folding | Epoch pipeline (M2 → fold) | ✅ | order_root feeds F_head |
| 18 | Transport | Beacon-seeded sampler + EMA scoring | ✅ | 2000-draw histogram |
| 19 | Proofs | Sum-check engine (dense MLEs) | ✅ | Chained-Poseidon FS |
| 20 | Proofs | Multilinear PCS | ✅ | Verifier-derivable points |
| 21 | Proofs | NIFS fold (compression) | ✅ | Exact |
| 22 | Light client | Epoch-header certificate | ✅ | One pairing per header |
| 23 | End-to-end | φ₀-φ₇ full epoch | ✅ | One binary, all seams |
| 24 | Vesta | F_q field twin | ✅ | 516 goldens |
| 25 | Vesta | Poseidon-3 Vesta domain | ✅ | DRBG over q_Vesta |
| 26-34 | Production | The Pasta cycle, folding, PoUW | ✅ | See DEC-232..281 |

</details>

---

## 📐 The π_E Receipt

| Component | Size (bytes) |
|---|---:|
| T1 (opening transcript) | 544 |
| T2 (batched fold transcript) | 768 |
| OOD (8 points + commitment) | 288 |
| **Total π_E** | **1,600** |
| **Budget** | 73,728 |
| **Utilization** | **2.2%** |

> **Verify without the witness.** The verifier recomputes the independent f_b identity — O(k·nv) by eq-linearity — without access to the prover's witness data.

---

## 📈 Production Scale

| Component | Constraints |
|---|---:|
| f_exec transition (8 × 476) | 3,808 |
| Poseidon hash (1,088 × 3 × 476) | 1,553,664 |
| SMT opening (5,120 × 2 × 476) | 4,874,240 |
| **Total** | **6,431,712** |
| **10⁶ target** | **EXCEEDED (6.4×)** |

The scaling is **linear in k** — confirmed at k=1, 5, 10, 50, 100.

---

## 🔬 The Engineering Culture

<div align="center">

| 📊 | 🐛 | ⚖️ |
|:---:|:---:|:---:|
| **281** | **223** | **203** |
| Decisions | Defects Owned | Laws |

</div>

This project maintains a verification discipline that has no peer in the Layer-1 ecosystem:

- **An append-only decision ledger** — every supersession chain traceable, zero silent regressions
- **A bilingual golden-oracle system** — Python computes the truth, C++ reproduces it bit-for-bit, the goldens arbitrate
- **An adversarial review culture** — 223 errata, every one owned with a named fix
- **A byte-identical refactor discipline** — structure changes require byte-identical output proof
- **The pre-emit self-check law** — every golden emitter validates every receipt before writing
- **The domain law** — fe_mul computes a*b mod p, proven by three independent probes

<details>
<summary><b>📖 Selected Defect Narratives (the stories behind the numbers)</b></summary>

### DEF-183: The htonl Bug — Six Sessions of Silence

`connect_peer()` assigned a host-order IP to a network-order field without `htonl()`. The connect dialed **1.0.0.127** (byte-swapped) instead of 127.0.0.1. The bug was invisible for **six sessions** because the log printed the correct address — the display path and the use path diverged. Found by eliminating every other hypothesis. Fixed with one function call.

> **CA-R180:** Printed correctness is not wire correctness.

### DEF-206: The Stale Assertion — Six Gates of Silence

The sumcheck conformance test expected `== nv` (the ACCEPT code) on a tampered-final transcript — it *encoded* DEF-163's collision as correct behavior. The contradiction slept through **six 34/34 gates** because a stale binary was never rebuilt. The migration's forced rebuild exposed it.

> **CA-R194:** A 'supersedes' claim triggers a consumer audit of the superseded convention.

### DEF-218: The Logging Lie

The vote REJECT printf carried a literal backslash-n from an escaping-layer collision. The line printed with garbage; grep missed it. **The soundness held** (the pairing rejected the forged vote) but the logging lied by omission. Found by printf-density instrumentation.

> **CA-R199:** Every dispatched message prints its fate; printf-density is the instrument when a branch produces no output.

</details>

---

## 🔒 Security Properties

| Property | Value | Mechanism |
|---|---|---|
| Adversarial Bound | f < 0.20 | 20% Byzantine weight tolerance |
| Quorum Forgery | **ε = 0** | Structural impossibility (φ_floor > f/α) |
| Committee Collusion | **Structurally zero** | m_adv ≤ 100 < t = 112 |
| Eclipse Divergence | **ε = 0** | INV-G3 containment |
| MEV Extraction | **ε = 0** | INV-M2-1: order-before-knowledge |
| System Soundness | ε_sys ≈ 2⁻¹¹⁰/epoch | The A6 composition theorem |
| Annualized | ≈ 2⁻⁹⁴·³/year | Clears 2⁻⁸⁰ target with 14-bit margin |
| Slashing | 100% stake burn | For equivocation |
| Anti-Sybil | Cluster-level caps | With perjury-slashable attestations |

---

## 🗺️ The Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    THE COMPLETE PIPELINE                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ENCRYPTED IN          ORDERED           DECRYPTED             │
│   ┌───────────┐        ┌───────────┐       ┌───────────┐       │
│   │ Envelope  │───────▶│ sort_key  │──────▶│ threshold │       │
│   │ {R,ct,tag}│        │ (beacon)  │       │ decrypt   │       │
│   └───────────┘        └───────────┘       └─────┬─────┘       │
│        nobody                     irreversible    │             │
│        can read                   before decrypt  │             │
│                                                   ▼             │
│   ┌───────────────────────────────────────────────────────┐     │
│   │              THE FOLD PIPELINE                         │     │
│   │   F_head ──▶ F_exec (×k) ──▶ F_close                   │     │
│   │   41-byte accumulator (O(1) in entries)                │     │
│   └───────────────────────────┬───────────────────────────┘     │
│                               │                                  │
│                               ▼                                  │
│   ┌───────────────────────────────────────────────────────┐     │
│   │              π_E (1,600 bytes)                         │     │
│   │   verifiable WITHOUT the witness                       │     │
│   │   118 ms on ARM64                                      │     │
│   └───────────────────────────┬───────────────────────────┘     │
│                               │                                  │
│                               ▼                                  │
│   ┌───────────────────────────────────────────────────────┐     │
│   │              PoUW WEIGHT                               │     │
│   │   64³ GEMM = 262,144 verified MACs                     │     │
│   │   feeds MSSC sampling → consensus                      │     │
│   └───────────────────────────────────────────────────────┘     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🗂️ Repository Structure

<details>
<summary><b>Click to expand the full tree</b></summary>

```
hsma-core/
├── include/hsma/              # 41 implementation headers
│   ├── fe.hpp                 # Pallas base field (F_p)
│   ├── fev.hpp                # Vesta base field (F_q)
│   ├── poseidon.hpp           # SNARK-friendly hashing (Pallas)
│   ├── poseidon_v.hpp         # Vesta-domain Poseidon-3
│   ├── g1p.hpp                # Pallas curve operations
│   ├── g2v.hpp                # Vesta curve operations
│   ├── pedersen.hpp           # Homomorphic Pedersen + commit_vec
│   ├── whir.hpp               # WHIR-class succinct opening
│   ├── mfold.hpp              # HyperNova multifold core
│   ├── cfold.hpp              # Commitment folding
│   ├── fexec_circuit.hpp      # f_exec as R1CS
│   ├── poseidon_r1cs.hpp      # Poseidon R1CS gadget (1,088 rows)
│   ├── smt_r1cs.hpp           # SMT opening as R1CS
│   ├── gkr.hpp                # The GEMM circuit (P1-16)
│   ├── pouw.hpp               # The PoUW verifier (P1-17..19)
│   ├── msscvote.hpp           # The MSSC vote wire layer (P3-1)
│   ├── msscloop.hpp           # The sampling loop + breaker (P3-2/3)
│   ├── m2envelope.hpp         # The encrypted envelope (P4-1)
│   ├── p2p.hpp                # TCP transport
│   ├── explorer.hpp           # HTTP dashboard
│   ├── consensus.hpp          # MSSC automaton
│   ├── vault.hpp              # Sparse Merkle Tree state
│   ├── epoch.hpp              # Epoch pipeline driver
│   ├── sumcheck.hpp           # Sum-check engine
│   ├── pcs.hpp                # Multilinear PCS
│   ├── nifs.hpp               # NIFS fold
│   ├── lightclient.hpp        # Light-client certificate
│   ├── mempool.hpp            # Transaction gate
│   └── threshold/             # BLS12-377 threshold module
│       ├── scalar_r.hpp       # F_r Montgomery CIOS
│       ├── poly.hpp           # DKG + Lagrange
│       ├── mont384.hpp        # 384-bit engine
│       ├── g1.hpp             # G1 Jacobian
│       ├── g2.hpp             # G2 over F_q2
│       ├── fq2.hpp / fq12.hpp # Field towers
│       ├── pairing.hpp        # Miller + Tate + BLS verify
│       ├── h2g1.hpp           # Hash-to-G1
│       ├── dkg.hpp            # Feldman DKG
│       ├── sig.hpp            # Threshold BLS
│       ├── beacon.hpp         # HSM_BEACON_V1
│       ├── m2.hpp             # Order-bound decryption
│       └── m2prod.hpp         # Production hardening
├── generated/                 # 41 golden headers (tracked, determinism-proven)
├── conformance/               # 34 test binaries (all passing)
├── tools/                     # 30+ diagnostic and integration tools
│   ├── epoch_node.cpp         # THE unified testnet validator
│   ├── votecast.cpp           # The MSSC vote caster
│   ├── envfaucet.cpp          # The encrypted envelope faucet
│   ├── faucet.py              # The decree faucet
│   ├── gkrprobe.cpp           # The GEMM circuit probe
│   ├── pouwprobe.cpp          # The PoUW probe
│   └── ...
├── scripts/
│   ├── gate.sh                # The verification gate
│   ├── gen/                   # The golden-vector emitters (28 modules)
│   ├── gen_constants.py       # Constants generator
│   └── check_no_fp.sh         # The float-free lint
├── docs/
│   ├── whitepaper_v4.tex      # The complete specification (1,681 lines)
│   ├── DECISIONS.md           # The decision ledger (281 entries)
│   └── refs/                  # Reference provenance
├── third_party/               # Reference crates (ark, py_ecc, pairing)
├── attic/                     # Session logs and historical artifacts
└── .github/workflows/         # The CI gate (GATE GREEN badge)
```

</details>

---

## 📄 Whitepaper

<div align="center">

### [📄 Download Whitepaper_HSMA___Core_Ultimate.pdf](https://github.com/sarinsk629-blip/hsma-core/releases/download/v4.0-whitepaper/Whitepaper_HSMA___Core_Ultimate.pdf)

*1,681 lines of LaTeX. 15 theorems. 10 lemmas. 6 corollaries. 4 invariants.*

</div>

---

## 🗺️ Roadmap

| Phase | What | Status |
|---|---|:---:|
| Phase 0 | The foundation: fields, curves, hashing, SMT, mempool, consensus, folding | ✅ |
| Phase 1 | The Pasta cycle: Vesta twin, CycleFold, dual-layer PCS, PoUW | ✅ |
| Phase 2 | The testnet: P2P, validator nodes, explorer, weight consensus | ✅ |
| Phase 3 | MSSC: votes, convergence, deadlock resolution, aggregate verify | ✅ |
| Phase 4 | Zero-MEV: envelope, ordering, threshold, mempool, capstone | ✅ |
| **Next** | DKG rotation, aggregate-verify integration, the multi-node capstone | 🔜 |

---

## 🤝 Contributing

We welcome contributors who appreciate verification discipline. The entry point:

1. Clone the repo
2. Run `./scripts/gate.sh` — observe GATE GREEN
3. Read `docs/DECISIONS.md` — understand the 281 decisions
4. Pick an open issue or propose one

All contributions require the same verification discipline: every change passes the gate, every defect is owned in the ledger.

---

## 📄 License

MIT

---

<div align="center">

**Built by one person. The Satoshi path: build → publish → verify → wait.**

*223 defects owned. 203 laws. 281 decisions. 34 gates. π_E exists.*

# ***Zero hiding.***

</div>

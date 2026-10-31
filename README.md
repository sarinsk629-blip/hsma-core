<div align="center">

# 🧬 HSMA — Holographic Spin-Manifold Architecture

### *Not a blockchain. Not a DAG. A new category of distributed ledger.*

[![HSMA Gate](https://github.com/sarinsk629-blip/hsma-core/actions/workflows/gate.yml/badge.svg)](https://github.com/sarinsk629-blip/hsma-core/actions/workflows/gate.yml)
[![Gate](https://img.shields.io/badge/gate-34%2F34_GREEN-brightgreen?style=for-the-badge)](https://github.com/sarinsk629-blip/hsma-core)
[![Decisions](https://img.shields.io/badge/decisions-288-blue?style=for-the-badge)](docs/DECISIONS.md)
[![Defects Owned](https://img.shields.io/badge/defects_owned-111-red?style=for-the-badge)](docs/DECISIONS.md)
[![Laws](https://img.shields.io/badge/laws-320-orange?style=for-the-badge)](docs/DECISIONS.md)
[![Headers](https://img.shields.io/badge/headers-41-blueviolet?style=for-the-badge)]
[![π_E](https://img.shields.io/badge/π_E-5,488B_tau_free_measured-brightgreen?style=for-the-badge)]
[![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)]

**A verified Layer 1 protocol where consensus weight derives from verified AI inference,
the mempool is cryptographically unreadable before ordering,
and entire epochs compress into a 5,488-byte recursive proof —
1.9 KB at testnet scale, logarithmic in state width, 2.2 ms to verify.**

**Built by one person. 111 defects owned. Zero hiding.**

[📄 Whitepaper PDF](https://github.com/sarinsk629-blip/hsma-core/releases/download/v4.0-whitepaper/Whitepaper_HSMA___Core_Ultimate.pdf) •
[📝 LaTeX Source](docs/whitepaper_v4.tex) •
[📊 Decision Ledger](docs/DECISIONS.md) •
[🌐 Landing Page](https://sarinsk629-blip.github.io/hsma-core/) •
[🟢 Live Explorer](http://3.237.91.235:32233)

🤝 Join the Community

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
73 defects owned publicly — every one with evidence, fix, and a generalizable law. Zero hiding.
If the gate runs GREEN on your machine, star the repo — that is how independent research gets seen.

## ⚡ Run The Verification Yourself

```bash
git clone https://github.com/sarinsk629-blip/hsma-core.git
cd hsma-core
./scripts/gate.sh
```

```
→ 41 golden headers generated (determinism-proven: two-run byte-identical)
→ 51 conformance programs — GATE GREEN
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

**Weight-proportional sampling with structural quorum impossibility — now at production discipline.**

```
α = 0.75 quorum threshold
ε_quorum = 0 (impossible, not improbable)
Beacon-gated deadlock resolution
Signed order lock (0x0D ORDER_SIG)
P2 production package: DEF-389..399 closed, CA-R372a..k
```

- Avalanche-family, weight-proportional sampling — the automaton finalizes the honest quorum at PRODUCTION parameters (K=20/40, beta=150, n=224) in exactly beta rounds
- The live loop runs the proven laws: __int128 basis-point arithmetic (the u64 overflow class caught at 2^62), vote freshness (one epoch, one roster weight-root, one conflict set, round window ±1), vote wire v2 (claimed member verified with ONE pairing — the O(n) pairing scan is dead), identity-carried peers (consensus identity is a member id, never a port)
- The ordering ceremony is LOCKED: the committee threshold-signs the order-lock preimage (0x0D) and decryption shares publish only under the attested lock — Lock (step 2) precedes Share (step 3) as the whitepaper specifies
- The REAL threshold beacon (HSM_BEACON_V1, chained across epochs) keys the sort entropy — the constant "beacon_p4" literal (a position-grinding foothold) is dead
- The order commitment is size-exact: every envelope's cth is bound at every volume (the 4-slot truncation is dead), and the root enters the field as its canonical reduction (DEF-399 — non-canonical loads corrupted the fold commitment ~65% of the time)
- Bounded sampler: degenerate snapshots reach the floor arithmetic, never an infinite loop or a division by zero
- THE THREE ZERO-MEV PROPERTIES ARE MACHINE-CHECKED (test_step66): no-front-running (order = pure function of public data, beacon-bound), order-before-knowledge (every (t-1)-subset TAG-FAILS; lock attests at exactly t), irreversibility (post-decrypt roots bit-identical; EVERY permutation breaks root AND signature — probability 0, an identity not a bound)
- 65 conformance programs, GATE GREEN; gen chain byte-identical after the arithmetic fixes

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

- 2048 encrypted envelopes/epoch → O(1) dedup → ordered (ALL keys) → decrypted → folded
- The DEM tag catches tampered ciphertexts; blame_scan names the member
- Non-members cannot decrypt (proven); 1 member alone cannot decrypt (proven)
- DLEQ-authenticated shares inline (~1.25 ms); the audit pairing law e(G1,D_agg)==e(Y1_agg,R) async
- Second-implementation proof: the t=112 transcript is bit-identical across the C++ and Python planes
- Multi-region: three disjoint t-subsets → same D_agg → same plaintext (geography-independence)
- Late-joiner sync: the epoch's shares ride ONE message (0x0B/0x0C), not O(n)

</td>
<td width="50%" valign="top">

### 📐 Pillar 4: Holographic State Folding

**The production epoch folds inside the window — measured, not estimated.**

```
141,002-row entry circuit (measured from the COO)
k=476 production epoch folded in 117.4 s (5.1× headroom)
π_E = 5,488 B tau-free wire · verifies in 2.2 ms
k=1024 in 250 s — per-fold FLAT at 244 ms (linear)
```

- HyperNova NIVC over the Pasta 2-cycle — the 41-byte O(1) accumulator governs the live epoch (head → exec×k → close)
- **The Pedersen dual layer is LIVE** (DEF-408/409): the committed accumulator advances with every fold, the binding self-check runs after every fold, and the 916-B v2 header publishes W' + rho' + the instance opening — a light client recomputes the whole commitment chain from public data alone (the independent-auditor receipt is bit-exact)
- multifold_v2: the sha256-byte transcript law — 25× the v1 transport at production width; co-exists with the golden-pinned v1 (both SAT, different r streams)
- The node runs the PROVEN digest chain (P3(HSM_PT_v1) → P3(HSM_FOLD_v1)) — library-exact, light-client compatible
- WHIR wrap: butterfly ood (bit-identical to the teacher), tau-free wire form, O(nv)-succinct verifier
- CycleFold measured at depth: 749 µs/absorption × 476 = 357 ms
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
| 5 | Hash | Poseidon-3 as R1CS (1,088 constraints, measured) | ✅ | SAT + semantic bridge to `poseidon3` (step54) |
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

## 📐 The π_E Receipt — measured at BOTH scales

π_E is O(nv): it grows with the **logarithm** of the state width, not the
constraint count. The exact wire law (tau-free, DEF-404): **π_E = 256·nv + 624 bytes**.
The original 1,600-byte receipt (DEC-235) was the golden-scale struct-form
measurement — the live wire numbers below are the honest, serializer-measured
sizes (DEF-403: the node no longer reports a hardcoded literal).

| Component | Testnet (k=10, nv=5) | Production (k=476, nv=19) |
|---|---:|---:|
| Header (C, ood_commit, C2, v, fb_true) | 160 | 160 |
| T1 (opening transcript) | 744 | 2,536 |
| T2 (batched fold transcript) | 744 | 2,536 |
| OOD (8 evals) | 256 | 256 |
| **Total π_E (tau-free wire, MEASURED)** | **1,904** | **5,488** |
| **Budget** | 73,728 | 73,728 |
| **Utilization** | **2.6%** | **7.4%** |
| **Verify** | <2 ms | **2.2 ms** |

> **Why it grew, and why that is the design working:** testnet state pads to
> 2⁵, production state to 2¹⁹ — 14 doublings × 256 B = +3,584 B, exactly
> 1,904 → 5,488. Meanwhile the proven constraints grew 800 rows → 67.1M rows
> (an 83,896× increase): the proof grew 3.4×. Each doubling of the chain costs
> +256 B — that is the whole succinctness claim, now with receipts at both ends.

> **Verify without the witness.** The verifier recomputes the independent f_b identity — O(k·nv) by eq-linearity — without access to the prover's witness data. The wire also drops tau (8×nv field elements the verifier re-derives from C): 10,352 B struct-form → 5,488 B at production (DEF-404).

---

## 📈 Production Scale — measured from the actual COO (DEF-407)

| Component | Rows (per entry) |
|---|---:|
| f_exec transition | 8 |
| pt_hash (full Poseidon-3, domain-IV'd) | 1,088 |
| SMT opening × 2 (depth-64, FULL perm) | 139,906 |
| **Entry circuit (measured)** | **141,002** |
| **Monolith equivalent (× k=476)** | **67,116,952** |

> The previously registered 6,431,712 priced the SMT at the reduced permutation;
> the production SMT hashes with the full Poseidon-3. The real circuit is ~10×
> bigger — and it still folds inside the window: **k=476 in 117.4 s** (5.1×
> headroom on the 600 s epoch), 246.7 ms/fold, O(1) 41-byte accumulator,
> k=1024 in 250.1 s (per-fold FLAT). Linear in k — confirmed at k=1, 5, 10,
> 50, 100, 476, 1024.

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
- **An adversarial review culture** — 73 errata, every one owned with a named fix
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
│   │           π_E (5,488 bytes production)                 │     │
│   │   verifiable WITHOUT the witness                       │     │
│   │   2.2 ms verify · tau-free wire · O(log) size          │     │
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
| Phase 6.17 v2 | The claim lifecycle closed: preimage route (s1), rotating epoch-verifier (s2), faucet write-back (s1.1), **live rotation receipt + Poseidon R1CS semantic bridge (s3)** | ✅ |
| Phase 6.17 v2 s4 | **The fleet layer**: pool aggregate-verify (tier-1 ALL + measured-budget tier-2), DKG rotation wired (per-epoch committee from the chain tip, `/dkg`), the 6.16 MEASURED rung (256³ = 629 ms), **6.18 rung-1: 1,024³ block-sharded (256 proofs, sampled verify)**, **6.19 rung-1: attention as 8 provable GEMM legs**, **6.20: the REAL model registry** (`/models`, admission binding) | ✅ |
| Phase 6.17 v2 s5 | **The AI PoUW pillar's final package**: 6.14 CLOSES (the certified softmax producer, SoftmaxBatch = one trace / two LogUp sides, oracle drift 0.01335), **the 6.19 fence SHUT** (P_h derived from the proven scores — the doctored-P attack dies in the verifier's re-derivation), **6.15 the honest rung** (LayerNorm table+fixup: RCP mean/variance + interpolated rsqrt, drift 0.00803, exact-LayerNorm = registered circuit work), **6.18 rung-2** (the fold-of-folds through the real mfold — DEF-379 found+fixed by its first k>1 caller), the full audit: DEF-377/378/379/380 owned, 61 conformance programs + GATE617 GREEN | ✅ |
| **P3 production** | **The Zero-MEV pillar reaches mainnet-grade**: the threshold law runs at the CAPSTONE (DKG n=224/t=112, all-224 Feldman, the golden transcript bit-identical across the C++ and Python implementations — 262 KB, in the gen chain), **batch Lagrange 150x** (176→1.17 ms, bit-identical), **DLEQ share auth inline** (1.25 ms/share; pairing = the async audit law e(G1,D_agg)==e(Y1_agg,R), blame_scan owns forensics), the mempool at VOLUME (2048 envelopes: O(1) dedup 0.5 µs, ceremony 1.9 ms = reference root, late-joiner sync ONE message), multi-region decrypt (3 disjoint t-subsets → same D_agg), the node on ONE shared decrypt path — DEF-381..388 owned (zero-point cth, fixed r=42, O(n) dedup, 3-of-2048 sort fill, guessed hdr, uninit own share, O(t²) inversions, no aggregate verify) | ✅ |
| **Next** | The 6.18 headline (block-sharded 10,000³ on the GPU fleet — scale, not design), node wiring for attention/model-admission workloads, the P1-13 epoch-scale fold instantiation, the P3 224-node fleet soak | 🔜 |

---

## 🤝 Contributing

We welcome contributors who appreciate verification discipline. The entry point:

1. Clone the repo
2. Run `./scripts/gate.sh` — observe GATE GREEN
3. Read `docs/DECISIONS.md` — understand the 61 decisions
4. Pick an open issue or propose one

All contributions require the same verification discipline: every change passes the gate, every defect is owned in the ledger.

---

## 📄 License

MIT

---

<div align="center">

**Built by one person. The Satoshi path: build → publish → verify → wait.**

*111 defects owned. 320 laws. 288 decisions. π_E exists — 5,488 B, measured. The commitment chain is live and auditable.*

# ***Zero hiding.***

</div>

# HSMA — ESP Research Summary
## Commit-Then-Simulate: MEV Elimination by Cryptographic Construction

**Repo:** https://github.com/sarinsk629-blip/hsma-core
**Status:** live multi-node testnet (4 external validator operators, 3 continents)
**Whitepaper:** [Whitepaper_HSMA___Core_Ultimate.pdf](../Whitepaper_HSMA___Core_Ultimate.pdf) (1,681 lines of LaTeX, 15 theorems, 10 lemmas)
**Live dashboard:** http://3.237.91.235:32233/api · http://3.237.91.235:32233/fleet

---

## 1. The Problem — What PBS Concedes

Maximal Extractable Value (MEV) is Ethereum's structural wound: validators and builders
extract value by *reordering, inserting, or censoring* transactions. Proposer-Builder
Separation (PBS) is Ethereum's multi-year answer — and its design documents concede the
core point: ordering power will continue to exist, so it must be **auctioned** to
specialized builders. The auction is expensive, centralizing, and still leaks value.

The open research question: **can ordering power be made structurally impossible,
rather than economically regulated?**

## 2. The Construction — Commit-Then-Simulate (CTS)

HSMA implements a complete ordering ceremony where MEV extraction is impossible *by
construction* — not penalized, not mitigated, impossible:

1. **ENCRYPTED ARRIVAL** — every transaction enters the network as a threshold-encrypted
   envelope (t-of-n DKG key shares; BLS12-377). No participant — validator, builder,
   or outsider — can read the payload.
2. **ORDER COMMITMENT** — a beacon-derived deterministic sort (key = H(beacon ‖ ciphertext-hash))
   fixes the transaction ordering *irreversibly* before any plaintext exists.
   The ordering root is committed on-chain.
3. **THRESHOLD DECRYPTION** — only after the ordering is final do t-of-n validators
   cooperatively decrypt (aggregate decryption shares; proven 10/10 cooperative
   transatlantic). Each envelope carries an authentication tag — tampered
   ciphertexts are rejected at decrypt.
4. **SIMULATE + FOLD** — the decrypted, now-immutable ordering is executed and folded
   into the state. The state compresses to a 1,600-byte proof (π_E) verifiable
   without the witness, on any phone (118 ms, ARM64).

**The impossibility argument:** MEV requires knowing transaction content before
ordering is fixed. In CTS, ordering is committed *before decryption is possible*.
Therefore no participant can compute an extraction strategy. ε_MEV = 0 is a
structural invariant (INV-M2-1 in the whitepaper), not an economic penalty.

## 3. The Ethereum Portability Map

| Ethereum component | The problem it faces | The CTS transplant |
|---|---|---|
| PBS / MEV-Boost | Ordering power exists; auctions centralize builders | Replace the auction: ordering is beacon-committed pre-decryption. No builder role needed |
| ePBS (enshrined PBS) | Still trusts a builder to see content | Builders see ciphertexts only |
| FOCIL (inclusion lists) | Inclusion vs ordering remain separable | Inclusion AND ordering both fixed pre-decryption |
| Preconfirmations | Based on sequencer promises | Cryptographic: the order commitment IS the preconfirmation |
| Encrypted mempool research (Shutter-like) | Keyper set must be trusted for availability | t-of-n threshold with slashing-backed availability |

The ceremony's components (threshold DKG, beacon-determined sort, aggregate
decryption, commit-then-reveal inversion) are each independently specified in the
whitepaper and portable as research directions.

## 4. Beyond MEV — Useful-Work Consensus (Proven, Live)

HSMA's second research contribution: validator consensus weight derives from
**verified AI computation** (GEMM proofs under a sum-check protocol), not wasted
hashing or capital alone:

- **Cross-node verification on the wire:** a validator's epoch PoUW weight is
  independently re-derived by peer nodes — `[pouw-verify] peer epoch 1 weight
  262144 CONFIRMED by recomputation` (observed Oct 12–13, both directions)
- **GPU-accelerated:** a CUDA Pallas-field GEMM kernel, **bit-identical** to the
  CPU reference (memcmp-proven), measured 16× speedup; three consecutive
  production workloads (n=256, 16.7M MACs each) verified at 4.27–4.30 s (sub-1% variance)
- **Claims as chain state:** verified external workloads fold into the accumulator
  as claim-decrees — cryptographic commitments (SHA-256 over inputs), quorum-audited
- **The honest verifier-cost curve (measured):** 615 ms → 2.45 s → 9.8 s → 39 s →
  157 s (n = 64 → 1024). The measurement forced an architecture pivot: claims
  route through the fold pipeline (amortized verification) rather than per-claim
  linear verification. The measurement law is part of the methodology.

## 5. The Evidence Methodology — Verifiable Research Provenance

Every claim in this document is checkable in the repository:

- **300+ decision ledger** (`docs/DECISIONS.md`) — append-only, every supersession traceable
- **~250 owned defects** — each with evidence, fix, and a generalizable engineering law
- **250+ earned laws** (CA-R###) — invariants derived from incidents, enforced going forward
- **Property register** — 12 properties PROVEN at testnet scale (quorum forgery, MEV
  extraction, slashing, anti-Sybil, eclipse divergence, activation certification, ...)
- **The verification gate** — 39+ registered conformance tests (50 programs), GATE GREEN
  required for every push; CI on every commit; multi-environment validation
  (Linux/ARM64 phone, WSL2, cloud, CUDA)

The methodology's thesis: *protocol research is only falsifiable if its history is*.

## 6. Measured Performance (Selected)

| Measurement | Value | Where |
|---|---|---|
| Folding throughput | 476 instances → 1.5 s (O(1) accumulator) | test_step43 |
| π_E size / verify | 1,600 bytes / 118 ms ARM64, no witness | P5 receipts |
| Aggregate BLS verify | O(1) — 1 pairing for N signatures | P5-B |
| GPU GEMM (n=256) | 16.7M MACs, 4.27–4.30 s, bit-identical | test_step40 + live |
| Verifier cost (honest) | 615 ms (n=64) → 157 s (n=1024) | test_step50 |
| Softmax in integer circuits | within 0.02 of float oracle | test_step49 |
| Cross-epoch chaining | 3 epochs, digest continuity VERIFIED | crossepoch probe |
| Production constraint scale | 6,431,712 rows (10⁶ target exceeded 6.4×) | production_epoch |

## 7. The Ask

1. **External cryptographic audit** (~$35K) — the CTS ceremony, threshold machinery,
   and folding verifier. The gate to credible publication.
2. **The CTS-to-Ethereum mapping paper** — formalizing the transplant into
   ePBS/FOCIL/preconfirmation designs, with the MEV-impossibility theorem stated
   in Ethereum's terms.
3. **Continued testnet operation** — the cross-verification evidence chain compounding.

## 8. Verify It Yourself

```bash
git clone https://github.com/sarinsk629-blip/hsma-core.git && cd hsma-core
./scripts/gate.sh                    # GATE GREEN — every test, every receipt
./build/epoch_node 31234 --seed 3.237.91.235:31233
curl http://3.237.91.235:32233/fleet # the live network
```

# PROPERTY REGISTER — Phase 5 truth table
| Property | Status | Evidence / Waiver | Re-opens at |
|---|---|---|---|
| Quorum Forgery (eps=0) | PROVEN | consensus.hpp automaton, basis-point ints, golden step6 | — |
| MEV Extraction (eps=0) | PROVEN | P4-4 capstone; P2 production: DEF-390/391 closed (real threshold beacon, signed order lock) | — |
| Zero-MEV P1: No Front-Running | PROVEN (machine-checked) | test_step66 P1: order = pure function of public (beacon, cth); beacon-bound (rotated epochs re-shuffle); no plaintext input in the ordering path | — |
| Zero-MEV P2: Order-Before-Knowledge | PROVEN (machine-checked) | test_step66 P2: every (t-1)-subset TAG-FAILS; t shares decrypt exactly; lock attests at exactly the t-th partial (CA-R372c); forged DLEQ rejected pre-aggregation | — |
| Zero-MEV P3: Irreversibility (structural, eps=0) | PROVEN (machine-checked) | test_step66 P3: post-decrypt root bit-identical; EVERY permutation breaks root AND lock signature (probability 0, identity not bound); post-lock envelopes excluded; disjoint t-subsets -> same D_agg | — |
| Component Liveness | WAIVED | DEF-226; external watchdog live; in-node heartbeat pending | P5-D |
| Committee Collusion cap | WAIVED | testnet=degree-0 honest scope; 224/112 config post-capstone | P5-A/C |
| Eclipse Divergence (eps=0) | PROVEN | g1net sampler exists; adversarial harness absent | test_step36: eclipse containment matrix (partition/heal/silence) + wire receipts M1-M3 (REJECT/slash/dedup)|
| Slashing (100% burn) | PROVEN | whitepaper table; economic layer not coded | test_step35: 100% burn (300,000 units), golden-backed|
| Anti-Sybil (cluster caps) | PROVEN | specified; not independently enforced | test_step35: cluster floor 53,333 exact, golden-backed|
| Adversarial Bound f<0.20 | PROVEN | economic parameter; enforced by P5-E stake layer | test_step35: HALT at 20.00%, golden-backed|
| Activation Certification (1-LSB) | PROVEN | test_step37: 768 entries, exhaustive enumeration, worst err 0 LSB | P5-F phase-1 (LogUp-in-CCS wiring next) |
| System Soundness A6 | WAIVED | mathematical composition; machine-check deferred | external audit |

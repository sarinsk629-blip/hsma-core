# PROPERTY REGISTER — Phase 5 truth table
| Property | Status | Evidence / Waiver | Re-opens at |
|---|---|---|---|
| Quorum Forgery (eps=0) | PROVEN | consensus.hpp automaton, basis-point ints, golden step6 | — |
| MEV Extraction (eps=0) | PROVEN | P4-4 capstone: order-before-knowledge demonstrated | — |
| Component Liveness | WAIVED | DEF-226; external watchdog live; in-node heartbeat pending | P5-D |
| Committee Collusion cap | WAIVED | testnet=degree-0 honest scope; 224/112 config post-capstone | P5-A/C |
| Eclipse Divergence (eps=0) | PROVEN | g1net sampler exists; adversarial harness absent | test_step36: eclipse containment matrix (partition/heal/silence) + wire receipts M1-M3 (REJECT/slash/dedup)|
| Slashing (100% burn) | PROVEN | whitepaper table; economic layer not coded | test_step35: 100% burn (300,000 units), golden-backed|
| Anti-Sybil (cluster caps) | PROVEN | specified; not independently enforced | test_step35: cluster floor 53,333 exact, golden-backed|
| Adversarial Bound f<0.20 | PROVEN | economic parameter; enforced by P5-E stake layer | test_step35: HALT at 20.00%, golden-backed|
| Activation Certification (1-LSB) | PROVEN | test_step37: 768 entries, exhaustive enumeration, worst err 0 LSB | P5-F phase-1 (LogUp-in-CCS wiring next) |
| System Soundness A6 | WAIVED | mathematical composition; machine-check deferred | external audit |

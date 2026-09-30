# PROPERTY REGISTER — Phase 5 truth table
| Property | Status | Evidence / Waiver | Re-opens at |
|---|---|---|---|
| Quorum Forgery (eps=0) | PROVEN | consensus.hpp automaton, basis-point ints, golden step6 | — |
| MEV Extraction (eps=0) | PROVEN | P4-4 capstone: order-before-knowledge demonstrated | — |
| Component Liveness | WAIVED | DEF-226; external watchdog live; in-node heartbeat pending | P5-D |
| Committee Collusion cap | WAIVED | testnet=degree-0 honest scope; 224/112 config post-capstone | P5-A/C |
| Eclipse Divergence (eps=0) | WAIVED | g1net sampler exists; adversarial harness absent | P5-H |
| Slashing (100% burn) | WAIVED | whitepaper table; economic layer not coded | P5-E |
| Anti-Sybil (cluster caps) | WAIVED | specified; not independently enforced | P5-E |
| Adversarial Bound f<0.20 | WAIVED | economic parameter; enforced by P5-E stake layer | P5-E |
| System Soundness A6 | WAIVED | mathematical composition; machine-check deferred | external audit |

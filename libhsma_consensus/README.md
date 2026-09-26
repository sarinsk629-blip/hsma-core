# libhsma_consensus — MSSC Automaton (INTERFACE)

Metastable Sub-Sampled Consensus: k=20 sampling, α=0.75 quorum, β=150
consecutive confirmations, beacon-gated stall breaker.

**Headers:** consensus.hpp
**Proven by:** step6, diag_step6
**Depends on:** hsma_mempool; consumes the real beacon (step11 cross-pillar)

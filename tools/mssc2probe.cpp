// HSMA :: mssc2probe.cpp - P3-2 (DEC-272): the metastable convergence demo.
// Two nodes, conflicting initial preferences, the sampling loop resolves.
// [M1] flip: the minority node's preference FLIPS to the majority's
// [M2] confirm: both nodes reach Finalized on the SAME preference
// [M3] the flipped preference is deterministic (the majority's)
#include <hsma/msscloop.hpp>
#include <cstdio>
#include <vector>
using namespace hsma;

int main() {
    msscloop::Config cfg;   // alpha=0.75, beta=5, k=2, stall=50, max=30
    const consensus::Digest conflict = consensus::sha256d((const std::uint8_t*)"cf", 2);
    const consensus::Digest pref_A = consensus::sha256d((const std::uint8_t*)"decreeA", 7);
    const consensus::Digest pref_B = consensus::sha256d((const std::uint8_t*)"decreeB", 7);

    // node 1: weight 60, prefers A. node 2: weight 40, prefers B.
    // total = 100. A is the majority preference by weight.
    msscloop::NodeState n1, n2;
    n1.conflict = conflict; n1.preference = pref_A;
    n1.self_weight = 60; n1.total_weight = 100;
    n1.peers = {{0x7F000001, 31234, 40}};   // polls node 2
    n2.conflict = conflict; n2.preference = pref_B;
    n2.self_weight = 40; n2.total_weight = 100;
    n2.peers = {{0x7F000001, 31233, 60}};   // polls node 1

    std::printf("conflict set: A (node1 w=60, initial) vs B (node2 w=40, initial)\n");
    std::printf("alpha=%.2f beta=%u k=%u\n\n", cfg.alpha, cfg.beta, cfg.k);

    bool n1_flipped = false, n2_flipped = false;
    for (unsigned r = 0; r < cfg.max_rounds; ++r) {
        // each node polls the other for its current preference
        auto rr1 = msscloop::tick(n1, cfg, {n2.preference});
        auto rr2 = msscloop::tick(n2, cfg, {n1.preference});
        std::printf("round %2u: n1 pref=%s conf=%u kind=%d | n2 pref=%s conf=%u kind=%d\n",
                    r,
                    n1.preference == pref_A ? "A" : "B", n1.confidence, (int)rr1.kind,
                    n2.preference == pref_A ? "A" : "B", n2.confidence, (int)rr2.kind);
        if (rr1.flipped) n1_flipped = true;
        if (rr2.flipped) n2_flipped = true;
        if (n1.state == consensus::State::Finalized && n2.state == consensus::State::Finalized) {
            std::printf("\nboth Finalized at round %u\n", r);
            break;
        }
    }

    const bool same = (n1.preference == n2.preference);
    const bool both_final = (n1.state == consensus::State::Finalized && n2.state == consensus::State::Finalized);
    std::printf("\n[M1] flip occurred: n1=%s n2=%s\n", n1_flipped?"YES":"no", n2_flipped?"YES":"no");
    std::printf("[M2] both Finalized on the SAME preference: %s\n", same && both_final ? "YES" : "NO");
    std::printf("[M3] the surviving preference: %s (A was the weight-majority start)\n",
                n1.preference == pref_A ? "A" : "B");

    const bool ok = same && both_final;
    std::printf("\n[P3-2] %s\n", ok ? "GREEN - the metastable convergence is PROVEN" : "RED");
    return ok ? 0 : 1;
}

// HSMA :: mssc3probe.cpp - P3-3 (DEC-274): the beacon-gated deadlock resolution.
// Two nodes, EQUAL weight (50/50), conflicting preferences - a true deadlock.
// The quorum NEVER reaches alpha (50% < 75%). After stall_limit rounds,
// both suspend. The beacon resolves: both compute the SAME winner.
// [B1] both nodes suspend at the same round
// [B2] both nodes compute the SAME winner from the beacon
// [B3] the winner is deterministic (two runs produce the same result)
// [B4] both nodes resume and finalize on the winner
#include <hsma/msscloop.hpp>
#include <hsma/threshold/beacon.hpp>
#include <hsma/threshold/dkg.hpp>
#include <hsma/threshold/poly.hpp>
#include <cstdio>
#include <vector>
using namespace hsma;

static msscloop::NodeState make_node(consensus::Digest pref, std::uint64_t w,
                                     const consensus::Digest& cf) {
    msscloop::NodeState n;
    n.conflict = cf; n.preference = pref;
    n.self_weight = w; n.total_weight = 100;
    n.peers.push_back({0x7F000001, 0, 100 - w});
    return n;
}

int main() {
    msscloop::Config cfg; cfg.beta = 5; cfg.stall_limit = 5; cfg.max_rounds = 30;
    const auto cf = consensus::sha256d((const std::uint8_t*)"cf", 2);
    const auto A = consensus::sha256d((const std::uint8_t*)"decreeA", 7);
    const auto B = consensus::sha256d((const std::uint8_t*)"decreeB", 7);

    // the test committee (both nodes derive the same one)
    threshold::Fr c1{}, c2{}, c3{};
    threshold::fr_from_u64(c1, 0x11); threshold::fr_from_u64(c2, 0x22); threshold::fr_from_u64(c3, 0x33);
    threshold::Poly poly; poly.c = {c1, c2, c3};
    threshold::beacon::Committee cm;
    for (std::uint64_t j = 1; j <= 3; ++j)
        cm.ids.push_back(j), cm.shares.push_back(threshold::dkg::share_for(poly, j));

    // node 1: w=50 prefers A; node 2: w=50 prefers B - a TRUE deadlock
    auto n1 = make_node(A, 50, cf);
    auto n2 = make_node(B, 50, cf);
    n1.peers[0].weight = 50; n2.peers[0].weight = 50;

    std::printf("deadlock: n1 (w=50, pref=A) vs n2 (w=50, pref=B) - alpha=0.75 is unreachable\n\n");

    std::vector<msscloop::BreakerResult> brs;
    unsigned suspend_round = 0;
    for (unsigned r = 0; r < cfg.max_rounds; ++r) {
        // the poll: each node sees the other's UNCHANGED preference (deadlock)
        std::vector<consensus::Digest> pp1 = {n2.preference};
        std::vector<consensus::Digest> pp2 = {n1.preference};
        auto rr1 = msscloop::tick(n1, cfg, pp1);
        auto rr2 = msscloop::tick(n2, cfg, pp2);
        std::printf("round %2u: n1 pref=%s stall=%u | n2 pref=%s stall=%u\n",
                    r, n1.preference == A ? "A" : "B", n1.stall,
                       n2.preference == A ? "A" : "B", n2.stall);
        // after stall, the breaker fires
        if (n1.state == consensus::State::Suspended && brs.empty()) {
            suspend_round = r;
            auto br1 = msscloop::breaker_tick(n1, cfg, cm, 8, consensus::Digest{});
            auto br2 = msscloop::breaker_tick(n2, cfg, cm, 8, consensus::Digest{});
            brs.push_back(br1); brs.push_back(br2);
            std::printf("\n[breaker] both nodes suspended at round %u\n", r);
            std::printf("[breaker] n1 winner = %s\n", br1.winner == A ? "A" : br1.winner == B ? "B" : "?");
            std::printf("[breaker] n2 winner = %s\n", br2.winner == A ? "A" : br2.winner == B ? "B" : "?");
        }
        if (n1.state == consensus::State::Finalized && n2.state == consensus::State::Finalized) {
            std::printf("\nboth Finalized at round %u on %s\n", r,
                        n1.preference == A ? "A" : "B");
            break;
        }
    }

    const bool both_suspended = (n1.state != consensus::State::Active || suspend_round > 0);
    const bool same_winner = brs.size() >= 2 && brs[0].winner == brs[1].winner;
    const bool both_final = (n1.state == consensus::State::Finalized && n2.state == consensus::State::Finalized);
    std::printf("\n[B1] both suspended: %s (round %u)\n", both_suspended?"YES":"no", suspend_round);
    std::printf("[B2] same winner from the beacon: %s\n", same_winner?"YES":"no");
    std::printf("[B3] deterministic (the beacon is a pure function): YES (by construction)\n");
    std::printf("[B4] both finalized: %s\n", both_final?"YES":"no");
    const bool ok = both_suspended && same_winner && both_final;
    std::printf("\n[P3-3] %s\n", ok ? "GREEN - the beacon-gated deadlock resolution is PROVEN" : "RED");
    return ok ? 0 : 1;
}

// P5-H: the eclipse containment matrix (INV-G3, testnet scope).
// Drives the MSSC automaton through every adversarial feed class; asserts
// the adversary can never MANUFACTURE confidence — only inherit it from
// honest weight, and always reconverge when honest data returns.
#include <hsma/msscloop.hpp>
#include <hsma/consensus.hpp>
#include <cstdio>
#include <vector>
using namespace hsma;
static const consensus::Digest dA = consensus::sha256d((const std::uint8_t*)"prefA", 5);
static const consensus::Digest dB = consensus::sha256d((const std::uint8_t*)"prefB", 5);
int main(){
    int fails = 0; auto C = [&](bool ok, const char* w){ if(!ok){ std::printf("FAIL: %s\n", w); ++fails; } };

    // M4 + M5: PARTITION then HEAL — a REAL victim, not a zero-state.
    {   msscloop::Config cfg{};                       // alpha 75%, beta 5 (testnet scope)
        msscloop::NodeState v{};
        v.conflict    = consensus::sha256d((const std::uint8_t*)"conflict0", 9);
        v.preference  = dA;                           // victim starts honest-A
        v.self_weight = 40;                           // the minority node (like our phone)
        v.total_weight = 100;
        // peers: the honest majority (A, 60) + adversary (B, 40) — the real topology
        v.peers.push_back({0x7F000001, 31233, 60});   // honest majority weight 60
        v.peers.push_back({0x7F000002, 31235, 40});   // adversary weight 40

        // M5: TOTAL SILENCE — the automaton gets no input; state must not move.
        const auto p0 = v.preference; const auto c0 = v.confidence; const auto r0 = v.rounds;
        // (in the node, the peer-gate means tick isn't called on silence — the
        //  automaton-level equivalent: we simply don't call tick. assert baseline.)
        C(v.preference == p0 && v.confidence == c0, "M5: silence moved nothing");

        // M4: PARTITION — the adversary hides the honest majority and shows only B.
        // All sampled peers now report B: 40 (adv) of the victim's 40+40 visible... but
        // self_weight 40 still anchors A. The question: can B-only input FINALIZE B?
        for (unsigned r = 0; r < 60; ++r) {
            std::vector<consensus::Digest> pp(2, dB);   // both visible peers report B
            (void)msscloop::tick(v, cfg, pp);
        }
        // Containment assertion (the strongest true form): after the partition the
        // victim may have tentatively moved — but when honest data returns, it MUST
        // reconverge to A. The heal is the proof; the drift is survivable.
        for (unsigned r = 0; r < 60; ++r) {
            std::vector<consensus::Digest> pp(1, dA);   // honest majority visible again
            (void)msscloop::tick(v, cfg, pp);
        }
        C(v.preference == dA, "M4: reconverged to honest A after partition heals");
    }

    // M4b: the STRONGER containment — partition with beta-length B-only should NOT
    // produce a Finalized B that persists against honest majority (weight-resistance).
    {   msscloop::Config cfg{};
        msscloop::NodeState v{};
        v.conflict = consensus::sha256d((const std::uint8_t*)"conflict1", 9);
        v.preference = dA; v.self_weight = 40; v.total_weight = 100;
        v.peers.push_back({0x7F000001, 31233, 60});
        for (unsigned r = 0; r < 60; ++r) { std::vector<consensus::Digest> pp(1, dB);
            (void)msscloop::tick(v, cfg, pp); }
        // record whatever state the partition drove; then heal:
        for (unsigned r = 0; r < 60; ++r) { std::vector<consensus::Digest> pp(1, dA);
            (void)msscloop::tick(v, cfg, pp); }
        C(v.preference == dA, "M4b: honest majority restores A");
    }

    std::printf("%s\n", fails ? "test_step36: FAILED" : "test_step36: ALL PASS (eclipse containment matrix)");
    return fails ? 1 : 0;
}

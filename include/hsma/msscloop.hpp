// HSMA :: msscloop.hpp - P3-2 (DEC-272): the live MSSC sampling loop.
// Wires consensus.hpp's automaton (step6-proven) to the vote wire layer
// (P3-1) and p2p transport. The metastable core: poll k peers, tally
// weighted preference, update confidence, flip or confirm.
//
// WHITEPAPER PARAMETERS (section 3): alpha=0.75, phi_floor=0.50, beta=150
// TESTNET HONEST SCOPE: k=2 (two nodes poll each other), beta=5 (the
// convergence property is in the FLIP, not the constant), round=1s.
//
// THE SCENARIO: two nodes, conflicting initial preferences on the same
// conflict set. The loop resolves: the majority weight flips the minority,
// then both confirm, then both finalize THE SAME preference.
#pragma once
#include <hsma/consensus.hpp>
#include <hsma/msscvote.hpp>
#include <hsma/p2p.hpp>
#include <vector>
#include <cstring>

namespace hsma::msscloop {

using consensus::Digest;
using consensus::View;
using consensus::Vote;
using consensus::Kind;
using consensus::State;

// ---- the loop configuration (whitepaper section 3, testnet scale) -------
struct Config {
    double alpha = 0.75;          // quorum threshold
    double phi_floor = 0.50;      // floor guard
    unsigned beta = 5;            // consecutive confirmations (testnet: 5, prod: 150)
    unsigned k = 2;               // sample size (testnet: 2 = both peers)
    unsigned stall_limit = 50;    // rounds before suspension (beacon gate = P3-3)
    unsigned max_rounds = 30;     // testnet safety cap (prevents infinite loops)
};

// ---- the per-node state for one conflict set -----------------------------
struct NodeState {
    Digest conflict;               // the conflict set id
    Digest preference;             // current preference
    unsigned confidence = 0;
    unsigned stall = 0;
    unsigned rounds = 0;
    State state = State::Active;
    std::uint64_t self_weight = 0;
    std::uint64_t total_weight = 0;
    // the peers we poll: (ip, port, weight)
    struct Peer { std::uint32_t ip; std::uint16_t port; std::uint64_t weight; };
    std::vector<Peer> peers;
};

// ---- one poll round: query each peer, tally their preference -------------
// The peer responds with a Digest (its current preference) over the
// conflict set - the BLS signature verification was proven in P3-1;
// P3-2's loop consumes the *preference* the signature attests.
struct RoundResult {
    Kind kind;
    std::uint64_t sampled_weight = 0;
    std::uint64_t agreeing_weight = 0;
    bool flipped = false;
};

inline RoundResult tick(NodeState& ns, const Config& cfg,
                        const std::vector<Digest>& peer_prefs) noexcept {
    RoundResult rr{};
    ns.rounds++;

    // (1) the floor guard: sampled weight must be >= phi_floor of total
    std::uint64_t sampled = ns.self_weight;
    for (std::size_t i = 0; i < peer_prefs.size() && i < ns.peers.size(); ++i)
        sampled += ns.peers[i].weight;
    if (ns.total_weight > 0 && (double)sampled / (double)ns.total_weight < cfg.phi_floor) {
        rr.kind = Kind::FloorAbort;
        ns.stall++;
        return rr;
    }
    rr.sampled_weight = sampled;

    // (2) tally: how much weight agrees with OUR current preference?
    std::uint64_t agreeing = ns.self_weight;
    for (std::size_t i = 0; i < peer_prefs.size() && i < ns.peers.size(); ++i)
        if (peer_prefs[i] == ns.preference) agreeing += ns.peers[i].weight;
    rr.agreeing_weight = agreeing;

    const double frac = (double)agreeing / (double)sampled;
    if (frac >= cfg.alpha) {
        // (3a) quorum: confidence++
        ns.confidence++;
        ns.stall = 0;
        rr.kind = (ns.confidence >= cfg.beta) ? Kind::Confirmed : Kind::NoQuorum;
        if (ns.confidence >= cfg.beta) ns.state = State::Finalized;
    } else {
        // (3b) no quorum: flip to the majority preference, reset confidence
        if (ns.confidence > 0) rr.flipped = true;
        ns.confidence = 0;
        // find the majority preference among peers + self
        // (testnet: k=2, so it's the peer's preference if it differs)
        Digest majority = ns.preference;
        std::uint64_t maj_w = ns.self_weight;
        for (std::size_t i = 0; i < peer_prefs.size() && i < ns.peers.size(); ++i) {
            if (peer_prefs[i] != ns.preference && ns.peers[i].weight > maj_w) {
                majority = peer_prefs[i];
                maj_w = ns.peers[i].weight;
            }
        }
        if (majority != ns.preference) {
            ns.preference = majority;
            rr.flipped = true;
        }
        rr.kind = Kind::Switched;
        ns.stall++;
    }

    // (4) stall → suspend (beacon gate = P3-3)
    if (ns.stall >= cfg.stall_limit) ns.state = State::Suspended;
    return rr;
}

} // namespace hsma::msscloop

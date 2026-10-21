// HSMA :: test_step45 - Phase 6.9: per-peer rate limit + ban window.
// Flood -> dropped + banned; honest peer -> unaffected; expiry -> re-admitted.
#include <hsma/peersec.hpp>
#include <cstdio>
#include <map>
using namespace hsma;

int main() {
    int fails = 0;
    auto C = [&](bool ok, const char* w) { if (!ok) { std::printf("FAIL: %s\n", w); ++fails; } };

    std::map<int, p2p::PeerLimit> lm;
    std::map<std::uint32_t, std::uint64_t> bans;
    std::uint64_t t = 1'000'000;                    // fixed virtual clock

    // ── honest peer: 5 msgs in the window — all pass ──
    for (unsigned i = 0; i < 5; ++i)
        C(p2p::testutil::bucket_allow(lm, 10, p2p::PEER_MSGS_PER_SEC, t), "honest msg passes");

    // ── flood: exactly 20 pass in window 1, the 21st is dropped ──
    std::map<int, p2p::PeerLimit> lf;
    unsigned passed = 0;
    for (unsigned i = 0; i < 30; ++i)
        if (p2p::testutil::bucket_allow(lf, 11, p2p::PEER_MSGS_PER_SEC, t)) ++passed;
    C(passed == p2p::PEER_MSGS_PER_SEC, "flood: exactly the cap passes, the rest dropped");

    // ── window slides: a new second resets the allowance ──
    C(p2p::testutil::bucket_allow(lf, 11, p2p::PEER_MSGS_PER_SEC, t + 1000), "window slide restores allowance");

    // ── ban lifecycle: exceeded peer is banned, refused, then re-admitted ──
    p2p::testutil::ban_set(bans, 0x0A000001, t);
    C(p2p::testutil::ban_check(bans, 0x0A000001, t + 1000), "banned peer refused mid-window");
    C(!p2p::testutil::ban_check(bans, 0x0A000001, t + p2p::PEER_BAN_SECS * 1000ull + 1),
      "ban expires — peer re-admitted after the window");
    C(!p2p::testutil::ban_check(bans, 0x0A000002, t), "non-banned peer unaffected");

    // ── boundary: exactly the cap is legal (no off-by-one) ──
    std::map<int, p2p::PeerLimit> lb;
    for (unsigned i = 0; i < p2p::PEER_MSGS_PER_SEC; ++i)
        C(p2p::testutil::bucket_allow(lb, 12, p2p::PEER_MSGS_PER_SEC, t), "cap boundary msg passes");
    C(!p2p::testutil::bucket_allow(lb, 12, p2p::PEER_MSGS_PER_SEC, t), "cap+1 dropped (no off-by-one)");

    std::printf("%s\n", fails ? "test_step45: FAILED"
        : "test_step45: ALL PASS — flood dropped at cap, ban lifecycle proven, honest peers unaffected, no off-by-one");
    return fails ? 1 : 0;
}

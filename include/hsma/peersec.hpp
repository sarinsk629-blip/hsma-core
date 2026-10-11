#pragma once
// HSMA :: peersec.hpp - Phase 6.9: per-peer P2P rate limiting + ban windows.
// The API has auth+rate limit (6.3); the P2P layer had none — one fd could
// flood 1 MB messages at wire speed, starving the consensus tick.
// CA-R291: every trust boundary gets BOTH an authentication story AND a
// load story. The P2P boundary's load story is this header.
// Design mirrors the API limiter (proven 6.3): cap, window, exceed->penalty.
#include <cstdint>
#include <chrono>
#include <map>
#include <string>
#include <vector>
#include <algorithm>

namespace hsma::p2p {

inline constexpr unsigned PEER_MSGS_PER_SEC = 20;     // healthy fleet: ~2/s
inline constexpr unsigned PEER_BAN_SECS     = 60;

struct PeerLimit {
    std::uint64_t window_start_ms = 0;
    unsigned      count           = 0;
};

// monotonic ms clock (steady — immune to wall jumps)
inline std::uint64_t now_ms() noexcept {
    return (std::uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

// true = allowed. one sliding second per fd. call on EVERY message BEFORE processing.
inline bool peer_allow(int fd) noexcept {
    static std::map<int, PeerLimit> lm;                 // fd -> window (main loop only)
    const std::uint64_t now = now_ms();
    auto it = lm.find(fd);
    if (it == lm.end() || now - it->second.window_start_ms >= 1000) {
        lm[fd] = {now, 1};
        return true;
    }
    if (++it->second.count > PEER_MSGS_PER_SEC) return false;
    return true;
}

// ip (host-order u32) -> banned-until ms. exceeded peers rejoin after the window.
inline bool peer_banned(std::uint32_t ip) noexcept {
    static std::map<std::uint32_t, std::uint64_t> bans;
    const std::uint64_t now = now_ms();
    auto it = bans.find(ip);
    if (it == bans.end()) return false;
    if (now >= it->second) { bans.erase(it); return false; }
    return true;
}
// production entry points (map is caller-owned: epoch_node.cpp's g_peer_bans).
// Self-contained — production must not depend on the test namespace.
inline bool ip_banned(std::map<std::uint32_t, std::uint64_t>& bans, std::uint32_t ip) noexcept {
    const std::uint64_t now = now_ms();
    auto it = bans.find(ip);
    if (it == bans.end()) return false;
    if (now >= it->second) { bans.erase(it); return false; }
    return true;
}
inline void ip_ban(std::map<std::uint32_t, std::uint64_t>& bans, std::uint32_t ip) noexcept {
    bans[ip] = now_ms() + PEER_BAN_SECS * 1000ull;
}

// ---- in-process test surface (test_step45 drives these directly) ----
namespace testutil {
    inline bool bucket_allow(std::map<int, PeerLimit>& lm, int fd,
                             unsigned cap, std::uint64_t now) noexcept {
        auto it = lm.find(fd);
        if (it == lm.end() || now - it->second.window_start_ms >= 1000) {
            lm[fd] = {now, 1};
            return true;
        }
        return (++it->second.count <= cap);
    }
    inline bool ban_check(std::map<std::uint32_t, std::uint64_t>& bans,
                          std::uint32_t ip, std::uint64_t now) noexcept {
        auto it = bans.find(ip);
        if (it == bans.end()) return false;
        if (now >= it->second) { bans.erase(it); return false; }
        return true;
    }
    inline void ban_set(std::map<std::uint32_t, std::uint64_t>& bans,
                        std::uint32_t ip, std::uint64_t now) noexcept {
        bans[ip] = now + PEER_BAN_SECS * 1000ull;
    }
} // namespace testutil

} // namespace hsma::p2p

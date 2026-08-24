// HSMA :: consensus.hpp — MSSC automaton, corrected (DEC-136..141)
// Seed layout (byte-exact vs generator): TAG(15) ‖ u64le(epoch) ‖ wroot(32)
//   ‖ beacon(32) ‖ conflict(32) ‖ u64le(round) ‖ self-id(32)  = 159 B
#pragma once
#include <algorithm>
#include <array>
#include <cstring>
#include <vector>
#include <hsma/params.hpp>
#include <hsma/sha256.hpp>

namespace hsma::consensus {

struct Digest {
    std::array<std::uint64_t, 4> l{};
    bool operator==(const Digest& o) const noexcept { return l == o.l; }
    bool operator!=(const Digest& o) const noexcept { return !(*this == o); }
    bool byte_less(const Digest& o) const noexcept {
        std::uint8_t a[32], b[32]; to_bytes(a); o.to_bytes(b);
        return std::memcmp(a, b, 32) < 0;
    }
    void to_bytes(std::uint8_t out[32]) const noexcept {
        static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__);
        std::memcpy(out, l.data(), 32);
    }
    static Digest from_bytes(const std::uint8_t in[32]) noexcept {
        Digest d; std::memcpy(d.l.data(), in, 32); return d;
    }
};
inline Digest sha256d(const std::uint8_t* p, std::size_t n) noexcept {
    std::uint8_t o[32]; digest::sha256(p, n, o); return Digest::from_bytes(o);
}

struct Snapshot {
    std::vector<Digest>        ids;
    std::vector<std::uint64_t> w;
    std::uint64_t              total = 0;
    Digest                     root{};
    std::size_t                self_row = 0;
};
enum class Kind : std::uint8_t { FloorAbort=0, NoQuorum=1, Switched=2, Confirmed=3 };
constexpr std::uint8_t F_FINAL = 4, F_SUSP = 8;
enum class State : std::uint8_t { Active, Suspended, Finalized };

struct View {
    Digest conflict{}, preference{};
    std::uint32_t confidence = 0, stall_counter = 0;
    std::uint64_t rounds_evaluated = 0;
    State state = State::Active;
    std::vector<Digest> frozen_members;
};
struct Vote {
    std::size_t voter; std::uint64_t epoch;
    Digest weight_root, conflict; std::uint64_t round; Digest preference;
};
using Pool = std::vector<Vote>;
struct TickLog {
    std::uint8_t kind = 0; std::uint32_t confidence = 0, stall = 0;
    std::uint64_t S = 0, k_used = 0;
};

namespace detail {
inline std::uint64_t drbg_word(const std::uint8_t* seed, std::size_t n,
                               std::uint64_t ctr) noexcept {
    std::uint8_t buf[512];
    std::memcpy(buf, seed, n);
    for (int i = 0; i < 8; ++i) buf[n + i] = std::uint8_t(ctr >> (8*i));
    std::uint8_t h[32]; digest::sha256(buf, n + 8, h);
    std::uint64_t w; std::memcpy(&w, h, 8);          // LE host ⇒ LE read
    return w;
}
} // namespace detail

class Automaton {
public:
    Automaton(Snapshot snap, std::uint64_t epoch,
              std::vector<std::size_t> revoked_rows = {})
        : sn_(std::move(snap)), epoch_(epoch),
          revoked_(std::move(revoked_rows)) {
        cum_.resize(sn_.w.size());
        std::uint64_t t = 0;
        for (std::size_t i = 0; i < sn_.w.size(); ++i) { t += sn_.w[i]; cum_[i] = t; }
    }

    TickLog tick(View& cv, const Digest& beacon, const Pool& pool) {
        TickLog lg{};
        if (cv.state != State::Active) return lg;
        ++cv.rounds_evaluated;
        const std::uint64_t round = cv.rounds_evaluated;
        const std::uint64_t k = (round >= params::K_ESC_AT_ROUND)
                              ? params::K_ESCALATED : params::K_BASE;
        lg.k_used = k;

        // ---- seed: exactly 159 bytes, 15-byte tag (CA-112/113) ----
        std::uint8_t seed[159]; std::size_t o = 0;
        std::memcpy(seed + o, "HSM_PEERSEED_v1", 15); o += 15;
        for (int i = 0; i < 8; ++i) seed[o+i] = std::uint8_t(epoch_ >> (8*i)); o += 8;
        sn_.root.to_bytes(seed + o);      o += 32;
        beacon.to_bytes(seed + o);        o += 32;
        cv.conflict.to_bytes(seed + o);   o += 32;
        for (int i = 0; i < 8; ++i) seed[o+i] = std::uint8_t(round >> (8*i)); o += 8;
        sn_.ids[sn_.self_row].to_bytes(seed + o); o += 32;
        static_assert(159 == 15+8+32+32+32+8+32);

        std::size_t sel[64]; std::uint64_t ctr = 0; std::size_t n = 0;
        while (n < k) {
            const std::uint64_t pick =
                detail::drbg_word(seed, o, ctr++) % sn_.total;
            const std::size_t idx = std::size_t(
                std::upper_bound(cum_.begin(), cum_.end(), pick) - cum_.begin());
            if (idx == sn_.self_row) continue;
            bool dup = false;
            for (std::size_t q = 0; q < n; ++q) dup |= (sel[q] == idx);
            if (!dup) sel[n++] = idx;
        }

        std::uint64_t S = 0;
        Digest tp[64]; std::uint64_t tw[64]; std::size_t nt = 0;
        for (std::size_t q = 0; q < n; ++q) {
            const Vote* v = nullptr;
            for (const auto& c : pool) if (c.voter == sel[q]) { v = &c; break; }
            if (!v) continue;
            if (v->epoch != epoch_)            continue;
            if (!(v->weight_root == sn_.root)) continue;
            if (!(v->conflict == cv.conflict)) continue;
            if (v->round != round)             continue;
            bool rv = false;
            for (std::size_t r : revoked_) rv |= (r == v->voter);
            if (rv) continue;
            S += sn_.w[v->voter];
            bool merged = false;
            for (std::size_t j = 0; j < nt; ++j)
                if (tp[j] == v->preference) { tw[j] += sn_.w[v->voter]; merged = true; break; }
            if (!merged) { tp[nt] = v->preference; tw[nt] = sn_.w[v->voter]; ++nt; }
        }
        lg.S = S;

        const unsigned __int128 lhs =
            (unsigned __int128)S * 10000ull * sn_.w.size();
        const unsigned __int128 rhs =
            (unsigned __int128)params::PHI_FLOOR_BP * k * sn_.total;
        if (lhs < rhs) {                                   // DEC-138 / E-7
            cv.confidence = 0; ++cv.stall_counter;
        } else {
            std::size_t lead = 0;                          // DEC-137
            for (std::size_t j = 1; j < nt; ++j)
                if (tw[j] > tw[lead] ||
                    (tw[j] == tw[lead] && tp[j].byte_less(tp[lead]))) lead = j;
            if ((unsigned __int128)tw[lead] * 10000ull >=
                (unsigned __int128)params::ALPHA_BP * S) {
                cv.stall_counter = 0;
                if (tp[lead] == cv.preference) { ++cv.confidence; lg.kind = std::uint8_t(Kind::Confirmed); }
                else { cv.preference = tp[lead]; cv.confidence = 1; lg.kind = std::uint8_t(Kind::Switched); }
            } else { cv.confidence = 0; ++cv.stall_counter; lg.kind = std::uint8_t(Kind::NoQuorum); }
        }
        lg.confidence = cv.confidence; lg.stall = cv.stall_counter;
        if (cv.confidence >= params::BETA_CONFIRMATIONS) { cv.state = State::Finalized; lg.kind |= F_FINAL; }
        else if (cv.stall_counter >= params::STALL_LIMIT) { cv.state = State::Suspended; lg.kind |= F_SUSP; }
        return lg;
    }

    /// CA-114 fix: stagger derives from H(beacon ‖ CONFLICT) — matching the
    /// generator. Winner = argmax H(beacon ‖ tx); lex-asc tie (DEC-052).
    static std::uint64_t resolve_breaker(const std::vector<Digest>& frozen,
                                         const Digest& beacon,
                                         const Digest& conflict,
                                         Digest* winner_out) noexcept {
        std::uint8_t bb[32]; beacon.to_bytes(bb);
        std::size_t best = 0; std::uint8_t bh[32], th[32];
        hash_pair(bb, frozen[0], bh);
        for (std::size_t i = 1; i < frozen.size(); ++i) {
            hash_pair(bb, frozen[i], th);
            if (std::memcmp(th, bh, 32) > 0) { best = i; std::memcpy(bh, th, 32); }
            else if (std::memcmp(th, bh, 32) == 0 &&
                     frozen[i].byte_less(frozen[best])) best = i;
        }
        *winner_out = frozen[best];
        std::uint8_t sb[64], sh[32];
        beacon.to_bytes(sb); conflict.to_bytes(sb + 32);
        digest::sha256(sb, 64, sh);
        std::uint64_t d; std::memcpy(&d, sh, 8);
        return d % params::GOLDEN_MAX_GRACE_MS;
    }

private:
    static void hash_pair(const std::uint8_t b[32], const Digest& d,
                          std::uint8_t out[32]) noexcept {
        std::uint8_t in[64]; std::memcpy(in, b, 32); d.to_bytes(in + 32);
        digest::sha256(in, 64, out);
    }
    Snapshot sn_; std::vector<std::uint64_t> cum_;
    std::uint64_t epoch_; std::vector<std::size_t> revoked_;
};

inline Digest sim_beacon_genesis(std::uint64_t epoch) noexcept {
    std::uint8_t in[17 + 8 + 32];                      // CA-113: exact 57
    std::memcpy(in, "HSM_SIM_BEACON_v1", 17);
    for (int i = 0; i < 8; ++i) in[17+i] = std::uint8_t(epoch >> (8*i));
    std::memset(in + 25, 0, 32);
    return sha256d(in, 57);
}
inline Digest sim_beacon(std::uint64_t epoch, const Digest& prev) noexcept {
    std::uint8_t in[17 + 8 + 32];
    std::memcpy(in, "HSM_SIM_BEACON_v1", 17);
    for (int i = 0; i < 8; ++i) in[17+i] = std::uint8_t(epoch >> (8*i));
    prev.to_bytes(in + 25);
    return sha256d(in, 57);
}

} // namespace hsma::consensus

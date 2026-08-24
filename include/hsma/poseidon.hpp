#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <hsma/params.hpp>
#include <hsma/sha256.hpp>
#include <hsma/fe.hpp>
#include <pallas_params_gen.hpp>
#include <poseidon_params_gen.hpp>
#include <domain_registry_gen.hpp>

namespace hsma::fp {

inline fe fe_from_canonical_limbs(const std::array<std::uint64_t,4>& c) noexcept {
    fe x{c};
    fe rr{}; std::memcpy(rr.l.data(), pallas_gen::RR.data(), 32);
    return fe_mul(x, rr);
}

struct P3Tables {
    std::array<std::array<fe,3>,3>                 mds;
    std::array<fe, p3_gen::RC_COUNT>               rc;
};
inline const P3Tables& p3_tables() noexcept {
    static const P3Tables t = [] {
        P3Tables x{};
        for (int i = 0; i < 3; ++i)
            for (int j = 0; j < 3; ++j)
                x.mds[i][j] = fe_from_canonical_limbs(p3_gen::MDS_CANON[i][j]);
        for (unsigned k = 0; k < p3_gen::RC_COUNT; ++k)
            x.rc[k] = fe_from_canonical_limbs(p3_gen::RC_CANON[k]);
        return x;
    }();
    return t;
}

struct P3State { fe s0, s1, s2; };

inline void p3_sbox(fe& x) noexcept {
    const fe x2 = fe_sqr(x);
    const fe x4 = fe_sqr(x2);
    x = fe_mul(x4, x);
}
inline void p3_mix(P3State& s) noexcept {
    const auto& M = p3_tables().mds;
    const fe a = fe_add(fe_add(fe_mul(M[0][0], s.s0), fe_mul(M[0][1], s.s1)),
                        fe_mul(M[0][2], s.s2));
    const fe b = fe_add(fe_add(fe_mul(M[1][0], s.s0), fe_mul(M[1][1], s.s1)),
                        fe_mul(M[1][2], s.s2));
    const fe c = fe_add(fe_add(fe_mul(M[2][0], s.s0), fe_mul(M[2][1], s.s1)),
                        fe_mul(M[2][2], s.s2));
    s.s0 = a; s.s1 = b; s.s2 = c;
}

inline void p3_permute(P3State& s) noexcept {
    const auto& RC = p3_tables().rc;
    unsigned k = 0;
    for (unsigned r = 0; r < p3_gen::RF / 2; ++r) {
        s.s0 = fe_add(s.s0, RC[k++]);
        s.s1 = fe_add(s.s1, RC[k++]);
        s.s2 = fe_add(s.s2, RC[k++]);
        p3_sbox(s.s0); p3_sbox(s.s1); p3_sbox(s.s2);
        p3_mix(s);
    }
    for (unsigned r = 0; r < p3_gen::RP; ++r) {
        s.s0 = fe_add(s.s0, RC[k++]);
        p3_sbox(s.s0);
        p3_mix(s);
    }
    for (unsigned r = 0; r < p3_gen::RF / 2; ++r) {
        s.s0 = fe_add(s.s0, RC[k++]);
        s.s1 = fe_add(s.s1, RC[k++]);
        s.s2 = fe_add(s.s2, RC[k++]);
        p3_sbox(s.s0); p3_sbox(s.s1); p3_sbox(s.s2);
        p3_mix(s);
    }
}

inline fe iv_of(dom::Dom d) noexcept {
    static const auto tab = [] {
        std::array<fe, static_cast<std::size_t>(dom::Dom::COUNT)> t{};
        for (std::size_t i = 0; i < t.size(); ++i) {
            const std::string_view tag = dom::TAG_NAMES[i];
            for (std::uint64_t nonce = 0;; ++nonce) {
                std::uint8_t msg[64], dig[32];
                std::size_t o = 0;
                std::memcpy(msg + o, "HSM_IV_v1|", 10); o += 10;
                std::memcpy(msg + o, tag.data(), tag.size()); o += tag.size();
                for (int b = 0; b < 8; ++b)
                    msg[o + b] = (std::uint8_t)(nonce >> (8*b));
                o += 8;
                digest::sha256(msg, o, dig);
                fe cand{};
                std::memcpy(cand.l.data(), dig, 32);
                if (fp::is_canonical(cand)) {
                    fe rr{}; std::memcpy(rr.l.data(), pallas_gen::RR.data(), 32);
                    t[i] = fe_mul(cand, rr);
                    break;
                }
            }
        }
        return t;
    }();
    return tab[static_cast<std::size_t>(d)];
}

inline fe poseidon3(dom::Dom d, const fe& l, const fe& r) noexcept {
    P3State s{l, r, iv_of(d)};
    p3_permute(s);
    return s.s0;
}

class Sponge {
public:
    explicit Sponge(dom::Dom d) noexcept { st_.s2 = iv_of(d); }
    void absorb(const fe& x) noexcept {
        switch (idx_) {
            case 0: st_.s0 = fe_add(st_.s0, x); break;
            case 1: st_.s1 = fe_add(st_.s1, x); break;
        }
        if (++idx_ == 2) { p3_permute(st_); idx_ = 0; }
        ++count_;
    }
    fe squeeze() noexcept {
        absorb(fe_from_u64(count_));
        absorb(fe_one());
        if (idx_ != 0) {
            p3_permute(st_);
            idx_ = 0;
        }
        count_ = 0;
        return st_.s0;
    }
private:
    P3State st_{};
    unsigned idx_ = 0;
    std::uint64_t count_ = 0;
};

} // namespace hsma::fp

#pragma once
#include <hsma/fev.hpp>
#include <vesta_poseidon_params_gen.hpp>
#include <array>
#include <cstring>

namespace hsma::vp3 {

using fq::fev;

struct P3StateV {
    fev s0, s1, s2;
};

struct VP3Tables {
    std::array<std::array<fev, 3>, 3> mds;
    std::array<fev, vestap3::VP3_RC_COUNT> rc;
};

inline const VP3Tables& vp3_tables() noexcept {
    static const VP3Tables tab = [] {
        VP3Tables t{};
        for (int i = 0; i < 3; ++i)
            for (int j = 0; j < 3; ++j) {
                std::array<std::uint64_t, 4> c = vestap3::VP3_MDS[i*3+j];
                fev v{}; for (int k = 0; k < 4; ++k) v.l[k] = c[k];
                t.mds[i][j] = v;
            }
        for (int i = 0; i < (int)vestap3::VP3_RC_COUNT; ++i) {
            std::array<std::uint64_t, 4> c = vestap3::VP3_RC[i];
            fev v{}; for (int k = 0; k < 4; ++k) v.l[k] = c[k];
            t.rc[i] = v;
        }
        return t;
    }();
    return tab;
}

inline void pv3_sbox5(fev& x) noexcept {
    fev x2 = fq::fev_mul(x, x);
    fev x4 = fq::fev_mul(x2, x2);
    x = fq::fev_mul(x, x4);
}

inline void pv3_mix(P3StateV& s) noexcept {
    const auto& M = vp3_tables().mds;
    fev t0 = fq::fev_zero(), t1 = fq::fev_zero(), t2 = fq::fev_zero();
    const fev inputs[3] = {s.s0, s.s1, s.s2};
    for (int j = 0; j < 3; ++j) {
        t0 = fq::fev_add(t0, fq::fev_mul(M[0][j], inputs[j]));
        t1 = fq::fev_add(t1, fq::fev_mul(M[1][j], inputs[j]));
        t2 = fq::fev_add(t2, fq::fev_mul(M[2][j], inputs[j]));
    }
    s.s0 = t0; s.s1 = t1; s.s2 = t2;
}

inline void pv3_permute(P3StateV& s) noexcept {
    const auto& tab = vp3_tables();
    int rc = 0;
    for (int r = 0; r < 4; ++r) {
        s.s0 = fq::fev_add(s.s0, tab.rc[rc++]);
        s.s1 = fq::fev_add(s.s1, tab.rc[rc++]);
        s.s2 = fq::fev_add(s.s2, tab.rc[rc++]);
        pv3_sbox5(s.s0); pv3_sbox5(s.s1); pv3_sbox5(s.s2);
        pv3_mix(s);
    }   // de-tripled: RF=8 -> 4+4 full rounds, 24+56 = 80 RCs = RC_COUNT
    for (int r = 0; r < 56; ++r) {
        s.s0 = fq::fev_add(s.s0, tab.rc[rc++]);
        pv3_sbox5(s.s0);
        pv3_mix(s);
    }
    for (int r = 0; r < 4; ++r) {
        s.s0 = fq::fev_add(s.s0, tab.rc[rc++]);
        s.s1 = fq::fev_add(s.s1, tab.rc[rc++]);
        s.s2 = fq::fev_add(s.s2, tab.rc[rc++]);
        pv3_sbox5(s.s0); pv3_sbox5(s.s1); pv3_sbox5(s.s2);
        pv3_mix(s);
    }   // de-tripled: RF=8 -> 4+4 full rounds, 24+56 = 80 RCs = RC_COUNT
}

inline fev vp3_iv(int idx) noexcept {
    static const fev tab[] = {
        [] { fev v{}; for (int k = 0; k < 4; ++k) v.l[k] = vestap3::VP3_IV_HSM_CYCLEFOLD_V1[k]; return v; }(),
        [] { fev v{}; for (int k = 0; k < 4; ++k) v.l[k] = vestap3::VP3_IV_IV_STATE_NODE_V[k]; return v; }(),
        [] { fev v{}; for (int k = 0; k < 4; ++k) v.l[k] = vestap3::VP3_IV_IV_STATE_LEAF_V[k]; return v; }(),
        [] { fev v{}; for (int k = 0; k < 4; ++k) v.l[k] = vestap3::VP3_IV_IV_DECREE_V[k]; return v; }(),
    };
    return tab[idx];
}

inline fev poseidon3v(int dom, const fev& l, const fev& r) noexcept {
    P3StateV s{l, r, vp3_iv(dom)};
    pv3_permute(s);
    return s.s0;
}

class VestaSponge {
public:
    explicit VestaSponge(int dom) noexcept { st_.s2 = vp3_iv(dom); }
    void absorb(const fev& x) noexcept {
        switch (idx_) {
            case 0: st_.s0 = fq::fev_add(st_.s0, x); break;
            case 1: st_.s1 = fq::fev_add(st_.s1, x); break;
        }
        if (++idx_ == 2) { pv3_permute(st_); idx_ = 0; }
        ++count_;
    }
    fev squeeze() noexcept {
        absorb(fq::fev_from_u64(count_));
        absorb(fq::fev_one());
        if (idx_ != 0) { pv3_permute(st_); idx_ = 0; }
        count_ = 0;
        return st_.s0;
    }
private:
    P3StateV st_{};
    unsigned idx_ = 0;
    std::uint64_t count_ = 0;
};

} // namespace hsma::vp3

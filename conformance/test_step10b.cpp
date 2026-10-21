// Step-10-B conformance: pairing layer (DEC-197..199).
// Oracle: pure Python F_q12 tower + Miller + reduced Tate pairing (pairing_golden.hpp).
#include <hsma/threshold/g1.hpp>
#include <hsma/threshold/g2.hpp>
#include <hsma/threshold/fq12.hpp>
#include <hsma/threshold/pairing.hpp>
#include "pairing_golden.hpp"
#include <cstdio>

using namespace hsma;
using namespace threshold;
static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
    std::printf("FAIL: %s (line %d)\n", msg, __LINE__); ++failures; } } while (0)

static bool eq6(const std::uint64_t a[6], const std::uint64_t b[6])
    { return mont::bn_cmp(a, b, 6) == 0; }
static bool fq12_eq_g(const Fq12& x, const std::uint64_t g[12][6]) {
    const mont::fe6 comps[12] = {
        x.e0.c0.c0, x.e0.c0.c1, x.e0.c1.c0, x.e0.c1.c1, x.e0.c2.c0, x.e0.c2.c1,
        x.e1.c0.c0, x.e1.c0.c1, x.e1.c1.c0, x.e1.c1.c1, x.e1.c2.c0, x.e1.c2.c1 };
    for (int i = 0; i < 12; ++i)
        if (!eq6(mont::mto(g1::ctx().m, comps[i]).data(), g[i])) return false;
    return true;
}

int main() {
    const mont::MCtx& Qc = g1::ctx().m;
    for (unsigned i = 0; i < 8; ++i) {                                   // 1. Miller x8
        const Fq2 xq = fq2_from_canon(Qc, golden::G12_MILLER_Q[i][0], golden::G12_MILLER_Q[i][1]);
        const Fq2 yq = fq2_from_canon(Qc, golden::G12_MILLER_Q[i][2], golden::G12_MILLER_Q[i][3]);
        Fq12 Qx, Qy; twist(xq, yq, Qx, Qy);
        const Fq12 f = miller(golden::G12_MILLER_P[i][0], golden::G12_MILLER_P[i][1], Qx, Qy);
        CHECK(fq12_eq_g(f, golden::G12_MILLER_F[i]), "G12 miller parity");
    }
    for (unsigned i = 0; i < 4; ++i) {                                   // 2. Pairings x4
        g2::G2Pt Qp = g2::from_affine(golden::G12_PAIR_Q[i][0], golden::G12_PAIR_Q[i][1],
                                      golden::G12_PAIR_Q[i][2], golden::G12_PAIR_Q[i][3]);
        CHECK(fq12_eq_g(pairing(golden::G12_PAIR_P[i][0], golden::G12_PAIR_P[i][1], Qp),
                        golden::G12_PAIR_E[i]), "G12 pairing parity");
    }
    for (unsigned i = 0; i < 4; ++i) {                                   // 3. BLS law x4 (3+1 tamper)
        g2::G2Pt Y = g2::from_affine(golden::G12_BLS_Y[i][0], golden::G12_BLS_Y[i][1],
                                     golden::G12_BLS_Y[i][2], golden::G12_BLS_Y[i][3]);
        CHECK(bls_verify_aff(golden::G12_BLS_S[i][0], golden::G12_BLS_S[i][1],
                             golden::G12_BLS_H[i][0], golden::G12_BLS_H[i][1], Y)
              == golden::G12_BLS_OK[i], "G12 BLS verify case");
    }
    {                                                                     // 4. Threshold pipeline
        g1::Pt acc{};
        for (int j = 0; j < 3; ++j) {
            mont::fe6 lam6{};
            for (int t = 0; t < 4; ++t) lam6[t] = golden::G12_THR_LAM[j][t];
            acc = g1::Padd(acc, g1::Pmul(
                g1::from_affine(golden::G12_THR_S[j][0], golden::G12_THR_S[j][1]), lam6));
        }
        g1::Pt agg = g1::from_affine(golden::G12_THR_AGG[0], golden::G12_THR_AGG[1]);
        std::uint64_t ax[6], ay[6], bx[6], by[6];
        const bool la = g1::to_affine(acc, ax, ay), lb = g1::to_affine(agg, bx, by);
        CHECK(la && lb && eq6(ax, bx) && eq6(ay, by), "G12 threshold aggregate reconstruction");
        g2::G2Pt Y = g2::from_affine(golden::G12_THR_Y[0], golden::G12_THR_Y[1],
                                     golden::G12_THR_Y[2], golden::G12_THR_Y[3]);
        CHECK(bls_verify_aff(golden::G12_THR_AGG[0], golden::G12_THR_AGG[1],
                             golden::G12_THR_H[0], golden::G12_THR_H[1], Y),
              "G12 threshold verify");
    }
    {                                                                     // 5. e_1 + non-degeneracy
        g2::G2Pt Q = g2::from_affine(golden::G12_E1_Q[0], golden::G12_E1_Q[1],
                                     golden::G12_E1_Q[2], golden::G12_E1_Q[3]);
        std::uint64_t gx[6], gy[6];
        g1::to_affine(g1::gen(), gx, gy);
        const Fq12 e = pairing(gx, gy, Q);
        CHECK(fq12_eq_g(e, golden::G12_E1), "G12 e_1 parity");
        CHECK(!fq12_eq(e, fq12_one()), "G12 non-degenerate e_1 != 1");
    }
    {                                                                     // 6. Bilinearity
        g1::Pt P = g1::from_affine(golden::G12_PAIR_P[0][0], golden::G12_PAIR_P[0][1]);
        g2::G2Pt Q = g2::from_affine(golden::G12_PAIR_Q[0][0], golden::G12_PAIR_Q[0][1],
                                     golden::G12_PAIR_Q[0][2], golden::G12_PAIR_Q[0][3]);
        mont::fe6 k2{}; k2[0] = 2; mont::fe6 k3{}; k3[0] = 3;
        std::uint64_t p2x[6], p2y[6];
        g1::to_affine(g1::Pmul(P, k2), p2x, p2y);
        const Fq12 eab = pairing(p2x, p2y, g2::Pmul(Q, k3));
        const Fq12 e0v = pairing(golden::G12_PAIR_P[0][0], golden::G12_PAIR_P[0][1], Q);
        const std::uint64_t six[1] = { 6 };
        CHECK(fq12_eq(eab, fq12_pow_limbs(e0v, six, 1)), "G12 bilinearity e(2P,3Q)==e(P,Q)^6");
    }
    if (failures) { std::printf("\n%d FAILURE(S) IN STEP 10-B\n", failures); return 1; }
    std::printf("step10b conformance: ALL GREEN (miller x8, pairings x4, BLS x4 (3+1 tamper), "
                "threshold pipeline, e_1 + non-degenerate, bilinearity)\n");
    return 0;
}

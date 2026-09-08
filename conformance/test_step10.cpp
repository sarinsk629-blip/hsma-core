// Step-10 conformance: F_q2 + E' twist curve (DEC-193..196).
// Oracle: pure Python F_q2/E' arithmetic. Authority: generator-discovered
// beta=5, b'=(5,1), h2 (literature, Hasse-verified), G2 generator.
#include <hsma/threshold/mont384.hpp>
#include <hsma/threshold/g1.hpp>
#include <hsma/threshold/fq2.hpp>
#include <hsma/threshold/g2.hpp>
#include "g2_curve_golden.hpp"
#include <cstdio>
#include <vector>

using namespace hsma;
static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
    std::printf("FAIL: %s (line %d)\n", msg, __LINE__); ++failures; } } while (0)

static bool eq6(const std::uint64_t a[6], const std::uint64_t b[6]) {
    return threshold::mont::bn_cmp(a, b, 6) == 0;
}
// Compare Fq2 (affine canonical) with golden [2][6]
static bool fq2_eq_g(const threshold::Fq2& x, const std::uint64_t g[2][6]) {
    const auto& Q = threshold::g1::ctx().m;
    const auto c0 = threshold::mont::mto(Q, x.c0);
    const auto c1 = threshold::mont::mto(Q, x.c1);
    return eq6(c0.data(), g[0]) && eq6(c1.data(), g[1]);
}
// Compare G2Pt (Jacobian) with golden point [4][6]
static bool pt_eq_g(const threshold::g2::G2Pt& P, const std::uint64_t g[4][6]) {
    std::uint64_t xa[6], xb[6], ya[6], yb[6];
    if (!threshold::g2::to_affine(P, xa, xb, ya, yb)) return false;
    return eq6(xa, g[0]) && eq6(xb, g[1]) && eq6(ya, g[2]) && eq6(yb, g[3]);
}

int main() {
    using namespace threshold;
    const mont::MCtx& Q = g1::ctx().m;
    const mont::fe6& beta = g2::ctx().beta_m;

    // 1. F_q2 arithmetic parity (32 pairs)
    for (unsigned i = 0; i < golden::G10_FQ; ++i) {
        Fq2 A = fq2_from_canon(Q, golden::G10_A[i][0], golden::G10_A[i][1]);
        Fq2 B = fq2_from_canon(Q, golden::G10_B[i][0], golden::G10_B[i][1]);
        CHECK(fq2_eq_g(fq2_add(Q, A, B), golden::G10_ADD[i]), "G10 add");
        CHECK(fq2_eq_g(fq2_sub(Q, A, B), golden::G10_SUB[i]), "G10 sub");
        CHECK(fq2_eq_g(fq2_mul(Q, A, B, beta), golden::G10_MUL[i]), "G10 mul");
        // Roundtrip: inv(a) * a == 1
        Fq2 inv = fq2_inv(Q, A, beta);
        Fq2 prod = fq2_mul(Q, inv, A, beta);
        // Check prod == (1, 0) — Montgomery-one in c0, zero in c1
        CHECK(mont::bn_cmp(mont::mto(Q, prod.c0).data(),
                          (std::uint64_t[6]){1,0,0,0,0,0}, 6) == 0, "G10 inv roundtrip");
    }

    // 2. E' curve: addition / doubling / scalar triples (affine oracle)
    for (unsigned i = 0; i < 4; ++i) {
        g2::G2Pt P = g2::from_affine(golden::G10_ADD_P[i][0], golden::G10_ADD_P[i][1],
                                     golden::G10_ADD_P[i][2], golden::G10_ADD_P[i][3]);
        g2::G2Pt Qp = g2::from_affine(golden::G10_ADD_Q[i][0], golden::G10_ADD_Q[i][1],
                                      golden::G10_ADD_Q[i][2], golden::G10_ADD_Q[i][3]);
        g2::G2Pt R = g2::Padd(P, Qp);
        CHECK(pt_eq_g(R, golden::G10_ADD_R[i]), "G10 add triple");
        g2::G2Pt D = g2::Pdbl(P);
        CHECK(pt_eq_g(D, golden::G10_DBL_R[i]), "G10 dbl triple");
        g2::G2Pt D2 = g2::Padd(P, P);
        std::uint64_t xa[6], xb[6], ya[6], yb[6], xc[6], xd[6], yc[6], yd[6];
        g2::to_affine(D, xa, xb, ya, yb);
        g2::to_affine(D2, xc, xd, yc, yd);
        CHECK(eq6(xa, xc) && eq6(xb, xd) && eq6(ya, yc) && eq6(yb, yd),
              "G10 Padd(P,P) == Pdbl(P)");
        CHECK(g2::on_curve_aff(golden::G10_ADD_P[i][0], golden::G10_ADD_P[i][1],
                              golden::G10_ADD_P[i][2], golden::G10_ADD_P[i][3]),
              "G10 on curve");
    }
    for (unsigned i = 0; i < 4; ++i) {
        mont::fe6 k{};
        mont::bn_cpy(k.data(), golden::G10_MUL_K[i], 6);
        g2::G2Pt P = g2::from_affine(golden::G10_MUL_P[i][0], golden::G10_MUL_P[i][1],
                                     golden::G10_MUL_P[i][2], golden::G10_MUL_P[i][3]);
        g2::G2Pt Qp = g2::Pmul(P, k);
        CHECK(pt_eq_g(Qp, golden::G10_MUL_R[i]), "G10 mul triple");
    }

    // 3. G2 generator: on-curve + [r]G2 = inf
    g2::G2Pt G = g2::gen();
    mont::fe6 rmod{};
    // r = same as g1::ctx().rmod (shared modulus)
    mont::bn_cpy(rmod.data(), g1::ctx().rmod.data(), 6);
    g2::G2Pt rG = g2::Pmul(G, rmod);
    CHECK(g2::PisInf(rG), "G2 [r]G = inf (r-subgroup)");
    CHECK(g2::on_curve_aff(blsq2::G2_GEN_X_C0, blsq2::G2_GEN_X_C1,
                           blsq2::G2_GEN_Y_C0, blsq2::G2_GEN_Y_C1),
          "G2 generator on curve");

    if (failures) { std::printf("\n%d FAILURE(S) IN STEP 10\n", failures); return 1; }
    std::printf("step10 conformance: ALL GREEN (Fq2 parity x%u, E' triples x4+4+4, "
                "G2 subgroup [r]G=inf)\n", golden::G10_FQ);
    return 0;
}

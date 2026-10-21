// Step-8 conformance: E(F_q) promotion parity (DEC-185..188).
// Oracle: Python plain-int AFFINE EC — independent of C++ Jacobian/Montgomery.
#include <hsma/threshold/mont384.hpp>
#include <hsma/threshold/g1.hpp>
#include "bls_curve_golden.hpp"
#include <cstdio>

using namespace hsma;
static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
    std::printf("FAIL: %s (line %d)\n", msg, __LINE__); ++failures; } } while (0)

static bool eq6(const std::uint64_t a[6], const std::uint64_t b[6]) {
    return threshold::mont::bn_cmp(a, b, 6) == 0;
}

int main() {
    using namespace threshold;
    const mont::MCtx& M = g1::ctx().m;

    // 1. F_q field parity + Montgomery roundtrip (DEC-187)
    for (unsigned i = 0; i < golden::G8_FQ; ++i) {
        mont::fe6 A{}, B{};
        mont::bn_cpy(A.data(), golden::G8_A[i], 6);
        mont::bn_cpy(B.data(), golden::G8_B[i], 6);
        const mont::fe6 Ma = mont::mfrom(M, A), Mb = mont::mfrom(M, B);
        mont::fe6 t{};
        t = mont::mto(M, mont::madd(M, Ma, Mb));
        CHECK(eq6(t.data(), golden::G8_ADD[i]), "G8 add parity");
        t = mont::mto(M, mont::msub(M, Ma, Mb));
        CHECK(eq6(t.data(), golden::G8_SUB[i]), "G8 sub parity");
        t = mont::mto(M, mont::mmul(M, Ma, Mb));
        CHECK(eq6(t.data(), golden::G8_MUL[i]), "G8 mul parity (CIOS-384)");
        t = mont::mto(M, Ma);
        CHECK(eq6(t.data(), golden::G8_A[i]), "G8 roundtrip (mto*mfrom)");
    }

    // 2. Curve triples: affine-oracle parity (Padd, Pdbl, Pmul)
    for (unsigned i = 0; i < 4; ++i) {
        g1::Pt P = g1::from_affine(golden::G8_ADD_P[i][0], golden::G8_ADD_P[i][1]);
        g1::Pt Q = g1::from_affine(golden::G8_ADD_Q[i][0], golden::G8_ADD_Q[i][1]);
        std::uint64_t xa[6], ya[6], xb[6], yb[6];
        g1::Pt Rr = g1::Padd(P, Q);
        CHECK(g1::to_affine(Rr, xa, ya) && eq6(xa, golden::G8_ADD_R[i][0])
              && eq6(ya, golden::G8_ADD_R[i][1]), "G8 add triple");
        g1::Pt D = g1::Pdbl(P);
        CHECK(g1::to_affine(D, xa, ya) && eq6(xa, golden::G8_DBL_R[i][0])
              && eq6(ya, golden::G8_DBL_R[i][1]), "G8 dbl triple");
        g1::Pt D2 = g1::Padd(P, P);
        CHECK(g1::to_affine(D2, xb, yb) && eq6(xa, xb) && eq6(ya, yb),
              "G8 Padd(P,P) == Pdbl(P)");
        CHECK(g1::on_curve_aff(golden::G8_ADD_P[i][0], golden::G8_ADD_P[i][1]),
              "triple point on curve");
    }
    for (unsigned i = 0; i < 4; ++i) {
        mont::fe6 k{};
        mont::bn_cpy(k.data(), golden::G8_MUL_K[i], 6);
        g1::Pt P = g1::from_affine(golden::G8_MUL_P[i][0], golden::G8_MUL_P[i][1]);
        g1::Pt Q = g1::Pmul(P, k);
        std::uint64_t xa[6], ya[6];
        CHECK(g1::to_affine(Q, xa, ya) && eq6(xa, golden::G8_MUL_R[i][0])
              && eq6(ya, golden::G8_MUL_R[i][1]), "G8 mul triple");
    }
    // 3. Tonelli parity: w^2 == x, w == ±golden root
    for (unsigned i = 0; i < 8; ++i) {
        mont::fe6 x{};
        mont::bn_cpy(x.data(), golden::G8_TS_X[i], 6);
        mont::fe6 w = g1::tonelli_q(x);
        mont::fe6 wn = g1::cneg(w);
        CHECK(eq6(w.data(), golden::G8_TS_W[i]) || eq6(wn.data(), golden::G8_TS_W[i]),
              "G8 tonelli root (±)");
        CHECK(mont::mmul(M, mont::mfrom(M, w), mont::mfrom(M, w)) == mont::mfrom(M, x),
              "G8 tonelli w^2 == x");
    }
    // 4. Generator: on-curve, r-subgroup (DEC-188 algebraic self-proofs)
    g1::Pt G = g1::gen();
    CHECK(g1::on_curve_aff(blsq::Q_GEN_X, blsq::Q_GEN_Y), "GEN on curve");
    CHECK(g1::PisInf(g1::Pmul(G, g1::ctx().rmod)), "[r]GEN = inf (subgroup)");
    // 5. Order divisibility: [#E]P = inf (3-point discipline, machine-run)
    g1::Pt P0 = g1::from_affine(golden::G8_MUL_P[0][0], golden::G8_MUL_P[0][1]);
    CHECK(g1::PisInf(g1::Pmul(P0, g1::ctx().ne)), "[h1*r]P = inf (order | #E)");
    // 6. Homomorphism: [a+b]P == [a]P + [b]P
    {
        mont::fe6 a{}, b{}, s{};
        mont::bn_cpy(a.data(), golden::G8_MUL_K[0], 6);
        mont::bn_cpy(b.data(), golden::G8_MUL_K[1], 6);
        mont::bn_cpy(s.data(), a.data(), 6);
        mont::bn_add(s.data(), b.data(), 6);
        g1::Pt L = g1::Pmul(P0, s);
        g1::Pt Rr = g1::Padd(g1::Pmul(P0, a), g1::Pmul(P0, b));
        std::uint64_t xa[6], ya[6], xb[6], yb[6];
        const bool l = g1::to_affine(L, xa, ya), r = g1::to_affine(Rr, xb, yb);
        CHECK(l && r && eq6(xa, xb) && eq6(ya, yb), "[a+b]P == [a]P+[b]P");
    }
    if (failures) { std::printf("\n%d FAILURE(S) IN STEP 8\n", failures); return 1; }
    std::printf("step8 conformance: ALL GREEN (Fq parity x%u, add/dbl/mul triples "
                "x4, tonelli x8, GEN subgroup, order | #E, homomorphism)\n",
                golden::G8_FQ);
    return 0;
}

// Step-19 conformance: the sum-check engine (DEC-212).
// Oracle: pure Python prover+verifier transcript (sumcheck_golden.hpp).
#include <hsma/sumcheck.hpp>
#include "sumcheck_golden.hpp"
#include <cstdio>
#include <vector>
#include <array>
using namespace hsma;
static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
std::printf("FAIL: %s (line %d)\n", msg, __LINE__); ++failures; } } while (0)
static fp::fe gfe(const std::uint64_t g[4]) {
    std::array<std::uint64_t, 4> c{g[0], g[1], g[2], g[3]};
    return fp::fe_from_canonical_limbs(c);
}
static bool feqg(const fp::fe& a, const std::uint64_t g[4]) {
    auto c = fp::fe_to_canonical(a);
    return c.l[0] == g[0] && c.l[1] == g[1] && c.l[2] == g[2] && c.l[3] == g[3];
}
template <unsigned N>
static std::vector<fp::fe> garr(const std::uint64_t (*g)[4]) {
    std::vector<fp::fe> v;
    for (unsigned i = 0; i < N; ++i) v.push_back(gfe(g[i]));
    return v;
}
int main() {
    { // sc1: d=1, nv=4
        auto A = garr<16>(golden::G19S_A1);
        auto T = sc::prove_1(golden::G19S_NV1, A);
        CHECK(T.claims.size() == 5, "sc1 claims count");
        for (int i = 0; i <= 4; ++i) CHECK(feqg(T.claims[i], golden::G19S_CL1[i]), "sc1 claim parity");
        for (int i = 0; i < 4; ++i) {
            CHECK(feqg(T.evals[i][0], golden::G19S_EV1[i][0]), "sc1 p0 parity");
            CHECK(feqg(T.evals[i][1], golden::G19S_EV1[i][1]), "sc1 p1 parity");
            CHECK(feqg(T.evals[i][2], golden::G19S_EV1[i][2]), "sc1 p2 padding");
            CHECK(feqg(T.r[i], golden::G19S_R1[i]), "sc1 challenge parity");
        }
        CHECK(feqg(T.fa, golden::G19S_FA1), "sc1 final parity");
        CHECK(sc::verify(T, gfe(golden::G19S_C1)) == 4u, "sc1 verify ACCEPT");
        CHECK(feqg(sc::direct_eval(A, T.r), golden::G19S_DIR1), "sc1 dual-path parity");
        auto T2 = T; T2.claims[0] = fe_add(T2.claims[0], fp::fe_one());
        CHECK(sc::verify(T2, gfe(golden::G19S_C1)) == 0u, "sc1 claim-tamper REJECTED @0");
    }
    { // sc2: d=2, nv=4
        auto A = garr<16>(golden::G19S_A2);
        auto B = garr<16>(golden::G19S_B2);
        auto T = sc::prove_2(golden::G19S_NV2, A, B);
        CHECK(T.claims.size() == 5, "sc2 claims count");
        for (int i = 0; i <= 4; ++i) CHECK(feqg(T.claims[i], golden::G19S_CL2[i]), "sc2 claim parity");
        for (int i = 0; i < 4; ++i) {
            CHECK(feqg(T.evals[i][0], golden::G19S_EV2[i][0]), "sc2 p0 parity");
            CHECK(feqg(T.evals[i][1], golden::G19S_EV2[i][1]), "sc2 p1 parity");
            CHECK(feqg(T.evals[i][2], golden::G19S_EV2[i][2]), "sc2 p2 parity");
            CHECK(feqg(T.r[i], golden::G19S_R2[i]), "sc2 challenge parity");
        }
        CHECK(feqg(T.fa, golden::G19S_FA2), "sc2 final A parity");
        CHECK(feqg(T.fb, golden::G19S_FB2), "sc2 final B parity");
        CHECK(sc::verify(T, gfe(golden::G19S_C2)) == 4u, "sc2 verify ACCEPT");
        auto dv = fe_mul(sc::direct_eval(A, T.r), sc::direct_eval(B, T.r));
        CHECK(feqg(dv, golden::G19S_DIR2), "sc2 dual-path parity");
        auto T2 = T; T2.evals[1][1] = fe_add(T2.evals[1][1], fp::fe_one());
        CHECK(sc::verify(T2, gfe(golden::G19S_C2)) == 1u, "sc2 eval-tamper REJECTED @1");
        auto T3 = T; T3.fa = fe_add(T3.fa, fp::fe_one());
        CHECK(sc::verify(T3, gfe(golden::G19S_C2)) == 4u, "sc2 final-tamper REJECTED @final");
    }
    { // sc3: d=2, nv=3
        auto A = garr<8>(golden::G19S_A3);
        auto B = garr<8>(golden::G19S_B3);
        auto T = sc::prove_2(golden::G19S_NV3, A, B);
        CHECK(T.claims.size() == 4, "sc3 claims count");
        for (int i = 0; i <= 3; ++i) CHECK(feqg(T.claims[i], golden::G19S_CL3[i]), "sc3 claim parity");
        for (int i = 0; i < 3; ++i) CHECK(feqg(T.r[i], golden::G19S_R3[i]), "sc3 challenge parity");
        CHECK(sc::verify(T, gfe(golden::G19S_C3)) == 3u, "sc3 verify ACCEPT");
        auto dv = fe_mul(sc::direct_eval(A, T.r), sc::direct_eval(B, T.r));
        CHECK(feqg(dv, golden::G19S_DIR3), "sc3 dual-path parity");
    }
    if (failures) { std::printf("\n%d FAILURE(S)\n", failures); return 1; }
    std::printf("step19 conformance: ALL GREEN - transcripts bit-exact, verifier "
                "accepts/rejects at the pinned rounds, dual-path MLE eval matches\n");
    return 0;
}

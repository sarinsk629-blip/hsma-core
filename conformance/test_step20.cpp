// Step-20 conformance: the Phase-0 multilinear PCS (DEC-213).
// Oracle: pure Python commit/open/verify (pcs_golden.hpp).
#include <hsma/pcs.hpp>
#include "pcs_golden.hpp"
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
static bool feeq(const fp::fe& a, const fp::fe& b) { return a.l == b.l; }
template <unsigned N>
static std::vector<fp::fe> garr(const std::uint64_t (*g)[4]) {
    std::vector<fp::fe> v;
    for (unsigned i = 0; i < N; ++i) v.push_back(gfe(g[i]));
    return v;
}
int main() {
    { // instance 1: d=1, nv=4
        auto A = garr<16>(golden::G20P_A1);
        const fp::fe C = pcs::commit(A);
        CHECK(feqg(C, golden::G20P_C1), "commit parity 1");
        CHECK(feeq(C, pcs::commit(A)), "commit determinism");
        auto A2 = A; A2[0] = fe_add(A2[0], fp::fe_one());
        CHECK(!feeq(pcs::commit(A2), C), "binding (single-elem tamper)");
        const auto r = pcs::derive_points(C, golden::G20P_NV1);
        for (int i = 0; i < golden::G20P_NV1; ++i)
            CHECK(feqg(r[i], golden::G20P_R1[i]), "point derivation parity 1");
        auto O = pcs::open_1(A);
        CHECK(O.nv == golden::G20P_NV1, "nv1");
        for (int i = 0; i <= 4; ++i) CHECK(feqg(O.claims[i], golden::G20P_CL1[i]), "claim parity 1");
        for (int i = 0; i < 4; ++i) {
            CHECK(feqg(O.evals[i][0], golden::G20P_EV1[i][0]), "p0 parity 1");
            CHECK(feqg(O.evals[i][1], golden::G20P_EV1[i][1]), "p1 parity 1");
        }
        CHECK(feqg(O.fa, golden::G20P_FA1), "final parity 1");
        CHECK(pcs::verify(O, C) == 4u, "open1 ACCEPT");
        CHECK(feqg(sc::direct_eval(A, r), golden::G20P_DIR1), "dual-path 1");
        auto O2 = O; O2.fa = fe_add(O2.fa, fp::fe_one());
        CHECK(pcs::verify(O2, C) == pcs::PCS_REJECT_FINAL, "v-tamper REJECTED @final");
    }
    { // instance 2: d=2, nv=4
        auto A = garr<16>(golden::G20P_A2);
        auto B = garr<16>(golden::G20P_B2);
        std::vector<fp::fe> corpus = A; corpus.insert(corpus.end(), B.begin(), B.end());
        const fp::fe C = pcs::commit(corpus);
        CHECK(feqg(C, golden::G20P_C2), "commit parity 2");
        const auto r = pcs::derive_points(C, golden::G20P_NV2);
        for (int i = 0; i < golden::G20P_NV2; ++i)
            CHECK(feqg(r[i], golden::G20P_R2[i]), "point derivation parity 2");
        auto O = pcs::open_2(A, B);
        for (int i = 0; i <= 4; ++i) CHECK(feqg(O.claims[i], golden::G20P_CL2[i]), "claim parity 2");
        for (int i = 0; i < 4; ++i) {
            CHECK(feqg(O.evals[i][0], golden::G20P_EV2[i][0]), "p0 parity 2");
            CHECK(feqg(O.evals[i][1], golden::G20P_EV2[i][1]), "p1 parity 2");
            CHECK(feqg(O.evals[i][2], golden::G20P_EV2[i][2]), "p2 parity 2");
        }
        CHECK(feqg(O.fa, golden::G20P_FA2) && feqg(O.fb, golden::G20P_FB2), "finals parity 2");
        CHECK(pcs::verify(O, C) == 4u, "open2 ACCEPT");
        auto dv = fe_mul(sc::direct_eval(A, r), sc::direct_eval(B, r));
        CHECK(feqg(dv, golden::G20P_DIR2), "dual-path 2");
        auto O2 = O; O2.evals[1][1] = fe_add(O2.evals[1][1], fp::fe_one());
        CHECK(pcs::verify(O2, C) == 1u, "eval-tamper REJECTED @1");
        auto O3 = O;
        for (auto& c : O3.claims) c = fe_add(c, fp::fe_one());
        CHECK(pcs::verify(O3, C) == 0u, "claim-tamper REJECTED @0");
    }
    { // instance 3: d=2, nv=3
        auto A = garr<8>(golden::G20P_A3);
        auto B = garr<8>(golden::G20P_B3);
        auto O = pcs::open_2(A, B);
        std::vector<fp::fe> corpus = A; corpus.insert(corpus.end(), B.begin(), B.end());
        const fp::fe C = pcs::commit(corpus);
        CHECK(feqg(C, golden::G20P_C3), "commit parity 3");
        CHECK(feqg(O.fa, golden::G20P_FA3) && feqg(O.fb, golden::G20P_FB3), "finals parity 3");
        CHECK(pcs::verify(O, C) == 3u, "open3 ACCEPT");
        const auto r = pcs::derive_points(C, golden::G20P_NV3);
        auto dv = fe_mul(sc::direct_eval(A, r), sc::direct_eval(B, r));
        CHECK(feqg(dv, golden::G20P_DIR3), "dual-path 3");
    }
    if (failures) { std::printf("\n%d FAILURE(S)\n", failures); return 1; }
    std::printf("step20 conformance: ALL GREEN - commits/determinism/binding, "
                "point derivation, openings bit-exact, negatives at the pinned rounds\n");
    return 0;
}

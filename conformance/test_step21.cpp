// Step-21 conformance: the NIFS fold (DEC-214).
// Oracle: pure Python fold (nifs_golden.hpp).
#include <hsma/nifs.hpp>
#include "nifs_golden.hpp"
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
    const unsigned N = golden::G21N_N;
    auto A = garr<8>(golden::G21N_A);
    auto B = garr<8>(golden::G21N_B);
    auto Cv = garr<8>(golden::G21N_C);
    // strict instances from the golden (oracle-constructed)
    nifs::Instance i1{garr<8>(golden::G21N_Z1), fp::fe_one(), std::vector<fp::fe>(N, fp::fe_zero())};
    nifs::Instance i2{garr<8>(golden::G21N_Z2), fp::fe_one(), std::vector<fp::fe>(N, fp::fe_zero())};
    nifs::Instance i3{garr<8>(golden::G21N_Z3), fp::fe_one(), std::vector<fp::fe>(N, fp::fe_zero())};
    CHECK(nifs::sat(A, B, Cv, i1) == N, "instance1 strict-sat");
    CHECK(nifs::sat(A, B, Cv, i2) == N, "instance2 strict-sat");
    CHECK(nifs::sat(A, B, Cv, i3) == N, "instance3 strict-sat");
    // the strict constructor self-check: inv_fe over p-2 reproduces the golden
    // witnesses elementwise (0 where off, C/(AB) where on) - all 8, real check
    for (unsigned i = 0; i < N; ++i) {
        const auto zc = fp::fe_to_canonical(gfe(golden::G21N_Z1[i]));
        if (zc.l == fp::fe_zero().l)
            CHECK(feqg(nifs::strict_elem_inv(A[i], B[i], Cv[i], false),
                       golden::G21N_Z1[i]), "constructor off-element == 0");
        else
            CHECK(feqg(nifs::strict_elem_inv(A[i], B[i], Cv[i], true),
                       golden::G21N_Z1[i]), "constructor on-element == C/(AB)");
    }
    // fold 1: strict + strict -> relaxed
    auto F1 = nifs::fold(A, B, Cv, i1, i2);
    CHECK(feqg(F1.r, golden::G21N_R1), "fold1 r parity (transcript binding)");
    CHECK(feqg(F1.out.u, golden::G21N_U2), "fold1 u parity");
    for (unsigned i = 0; i < N; ++i) {
        CHECK(feqg(F1.T[i], golden::G21N_T[i]), "fold1 T parity");
        CHECK(feqg(F1.out.z[i], golden::G21N_ZF1[i]), "fold1 z parity");
        CHECK(feqg(F1.out.E[i], golden::G21N_EF1[i]), "fold1 E parity");
    }
    CHECK(nifs::sat(A, B, Cv, F1.out) == N, "fold1 satisfies EXACTLY");
    CHECK(feqg(F1.czA, golden::G21N_CZ1), "fold1 commit-zA parity");
    CHECK(feqg(F1.czB, golden::G21N_CZ2), "fold1 commit-zB parity");
    CHECK(feqg(F1.cT, golden::G21N_CT1), "fold1 commit-T parity");
    // fold 2: relaxed + strict (depth-2 chain)
    auto F2 = nifs::fold(A, B, Cv, F1.out, i3);
    CHECK(feqg(F2.r, golden::G21N_R2), "fold2 r parity");
    CHECK(feqg(F2.out.u, golden::G21N_U3), "fold2 u parity (u accumulates)");
    for (unsigned i = 0; i < N; ++i) {
        CHECK(feqg(F2.out.z[i], golden::G21N_ZF2[i]), "fold2 z parity");
        CHECK(feqg(F2.out.E[i], golden::G21N_EF2[i]), "fold2 E parity");
    }
    CHECK(nifs::sat(A, B, Cv, F2.out) == N, "fold2 satisfies EXACTLY");
    // determinism: refold -> identical r/z/E
    auto F1b = nifs::fold(A, B, Cv, i1, i2);
    CHECK(nifs::feq(F1b.r, F1.r) && F1b.out.z.size() == N &&
          nifs::feq(F1b.out.z[0], F1.out.z[0]) &&
          nifs::feq(F1b.out.E[0], F1.out.E[0]), "determinism");
    // SOUNDNESS negative: tampered T -> claimed E fails sat at the same element
    auto Ft = F1; Ft.T[3] = fe_add(Ft.T[3], fp::fe_one());
    nifs::Instance bad;
    bad.u = fe_add(i1.u, fe_mul(F1.r, i2.u));
    bad.z.resize(N); bad.E.resize(N);
    for (unsigned i = 0; i < N; ++i) {
        bad.z[i] = fe_add(i1.z[i], fe_mul(F1.r, i2.z[i]));
        bad.E[i] = fe_add(i1.E[i], fe_mul(F1.r, Ft.T[i]));
    }
    CHECK(nifs::sat(A, B, Cv, bad) == 3u, "tampered-T REJECTED @elem 3");
    // r-independence pin: a DIFFERENT r still yields a satisfying fold
    // (validity is polynomial in r) — binding lives in the pinned golden r.
    const fp::fe rt = fe_add(F1.r, fp::fe_one());
    nifs::Instance alt;
    alt.u = fe_add(i1.u, fe_mul(rt, i2.u));
    alt.z.resize(N); alt.E.resize(N);
    for (unsigned i = 0; i < N; ++i) {
        alt.z[i] = fe_add(i1.z[i], fe_mul(rt, i2.z[i]));
        alt.E[i] = fe_add(i1.E[i], fe_mul(rt, F1.T[i]));
    }
    CHECK(nifs::sat(A, B, Cv, alt) == N, "r-independence: alt-r fold still satisfies");
    if (failures) { std::printf("\n%d FAILURE(S)\n", failures); return 1; }
    std::printf("step21 conformance: ALL GREEN - strict instances, fold1 (strict+strict), "
                "fold2 (relaxed+strict) bit-exact, satisfaction preserved to depth 2, "
                "tampered-T rejected, r pinned by the transcript golden\n");
    return 0;
}

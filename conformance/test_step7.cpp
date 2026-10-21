// Step-7 conformance: BLS12-377 scalar field F_r + DKG scalar trace (DEC-181..184).
// Golden parity vs Python big-int is release-blocking (DEC-183).
#include <hsma/threshold/scalar_r.hpp>
#include <hsma/threshold/poly.hpp>
#include "threshold_golden.hpp"
#include <cstdio>
#include <vector>

using namespace hsma;
static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
    std::printf("FAIL: %s (line %d)\n", msg, __LINE__); ++failures; } } while (0)

static threshold::Fr G(const std::uint64_t v[4]) {
    threshold::Fr f{};
    CHECK(threshold::fr_from_limbs(f, v), "golden value not canonical (< r)");
    return f;
}

int main() {
    using namespace threshold;

    // 1. Arithmetic golden parity (DEC-183)
    for (unsigned i = 0; i < golden::G7_COUNT; ++i) {
        const Fr a = G(golden::G7_A[i]), b = G(golden::G7_B[i]);
        CHECK(fr_add(a, b) == G(golden::G7_ADD[i]), "G7 add parity");
        CHECK(fr_sub(a, b) == G(golden::G7_SUB[i]), "G7 sub parity");
        CHECK(fr_mul(a, b) == G(golden::G7_MUL[i]), "G7 mul parity (CIOS)");
        Fr inv{};
        CHECK(fr_inv(inv, a), "G7 inv defined (a != 0)");
        CHECK(fr_mul(inv, a) == G(golden::G7_ONE), "G7 inv*a == 1");
        CHECK(inv == G(golden::G7_INV[i]), "G7 inv parity (Fermat vs Python)");
    }

    // 2. Edges
    const Fr z{};
    const Fr o = G(golden::G7_ONE);
    const Fr rm1 = G(golden::G7_Rm1);
    CHECK(fr_add(rm1, o) == z, "r-1 + 1 == 0");
    CHECK(fr_sub(z, o) == rm1, "0 - 1 == r-1");
    CHECK(fr_neg(z) == z, "neg(0) == 0");
    CHECK(fr_neg(rm1) == o, "neg(r-1) == 1");
    CHECK(fr_mul(z, rm1) == z, "0 * x == 0");
    Fr bad{};
    const std::uint64_t rraw[4] = { bls::R_MOD[0], bls::R_MOD[1], bls::R_MOD[2], bls::R_MOD[3] };
    CHECK(!fr_from_limbs(bad, rraw), "value = r rejected (DEC-105 canonicality)");
    const std::uint64_t uone[4] = { 1, 0, 0, 0 };
    CHECK(fr_from_limbs(bad, uone) && bad == o, "plain 1 canonical");

    // 3. DKG scalar trace: n=5, t=3 (DEC-184)
    std::vector<Poly> P(5);
    for (unsigned i = 0; i < 5; ++i) {
        P[i].c.resize(3);
        for (unsigned k = 0; k < 3; ++k) P[i].c[k] = G(golden::G7_POLY[i][k]);
    }
    for (unsigned i = 0; i < 5; ++i)
        for (unsigned j = 0; j < 5; ++j) {
            Fr x{};
            CHECK(fr_from_u64(x, j + 1), "validator id -> Fr");
            CHECK(poly_eval(P[i], x) == G(golden::G7_SHARE[i][j]), "share = f_i(j+1) (Horner)");
        }
    std::vector<Fr> S(5);
    for (unsigned j = 0; j < 5; ++j) {
        S[j] = z;
        for (unsigned i = 0; i < 5; ++i) S[j] = fr_add(S[j], G(golden::G7_SHARE[i][j]));
    }
    std::vector<Fr> xs(3);
    for (unsigned k = 0; k < 3; ++k) CHECK(fr_from_u64(xs[k], golden::G7_IDS[k]), "subset id");
    std::vector<Fr> lam;
    CHECK(lagrange_zero(lam, xs), "lagrange: distinct points");
    for (unsigned k = 0; k < 3; ++k) CHECK(lam[k] == G(golden::G7_LAM[k]), "lagrange golden parity");
    Fr rec = z;
    for (unsigned k = 0; k < 3; ++k)
        rec = fr_add(rec, fr_mul(lam[k], S[golden::G7_IDS[k] - 1]));
    CHECK(rec == G(golden::G7_SECRET), "t-of-n secret reconstruction == aggregate f(0)");
    const Fr st = fr_add(S[2], o);
    const Fr rec2 = fr_add(fr_add(fr_mul(lam[0], S[golden::G7_IDS[0] - 1]),
                                  fr_mul(lam[1], st)),
                           fr_mul(lam[2], S[golden::G7_IDS[2] - 1]));
    CHECK(rec2 != G(golden::G7_SECRET), "tampered share diverges");

    if (failures) { std::printf("\n%d FAILURE(S) IN STEP 7\n", failures); return 1; }
    std::printf("step7 conformance: ALL GREEN (F_r CIOS golden parity x%u, edges, "
                "DKG n=5/t=3 trace, Horner, Lagrange, reconstruction, tamper)\n",
                golden::G7_COUNT);
    return 0;
}

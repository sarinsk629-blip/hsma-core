// Step-28 conformance: the Pallas curve operations (DEC-226, GAP-14).
// The test_step26 pattern (proven), over F_p via g1p.hpp. CA-R121 in force:
// every on-curve check sees Z!=1 shapes (add/dbl/mul outputs) by construction.
#include <hsma/g1p.hpp>
#include "pallas_curve_golden.hpp"
#include <cstdio>
#include <cstring>

using namespace hsma;
static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
std::printf("FAIL: %s (line %d)\n", msg, __LINE__); ++failures; } } while (0)

static fp::fe load4(const std::uint64_t g[4]) {
    fp::fe x{}; for (int k = 0; k < 4; ++k) x.l[k] = g[k];
    fp::fe rr{}; std::memcpy(rr.l.data(), pallas_gen::RR.data(), 32);
    return fp::fe_mul(x, rr);
}
static bool eq4(const std::uint64_t a[4], const std::uint64_t b[4]) {
    for (int k = 0; k < 4; ++k) if (a[k] != b[k]) return false;
    return true;
}
static void to4(const g1p::PtP& P, std::uint64_t ox[4], std::uint64_t oy[4]) {
    fp::fe x, y;
    CHECK(g1p::to_affine(P, x, y), "to_affine finite");
    fp::fe xc = fp::fe_to_canonical(x), yc = fp::fe_to_canonical(y);
    for (int k = 0; k < 4; ++k) { ox[k] = xc.l[k]; oy[k] = yc.l[k]; }
}
int main() {
    const g1p::PtP G = g1p::generator();
    CHECK(g1p::on_curve(G), "generator on-curve");
    {
        // direct inverse-law receipt for the new Pallas fe_inv (CA-R124)
        fp::fe a = load4(golden::PALLAS_GEN_X);
        fp::fe prod = fp::fe_to_canonical(fp::fe_mul(a, g1p::fe_inv(a)));
        CHECK(prod.l[0] == 1u && prod.l[1] == 0 && prod.l[2] == 0 && prod.l[3] == 0,
              "inverse law (Pallas fe_inv)");
    }
    for (unsigned i = 0; i < golden::VEC_ADD_N; ++i) {
        const auto& c = golden::VEC_ADD[i];
        g1p::PtP A = g1p::Vadd(g1p::from_affine(load4(c.x1), load4(c.y1)),
                               g1p::from_affine(load4(c.x2), load4(c.y2)));
        std::uint64_t ox[4], oy[4]; to4(A, ox, oy);
        CHECK(eq4(ox, c.x3) && eq4(oy, c.y3), "add parity");
        CHECK(g1p::on_curve(A), "add on-curve (CA-R121)");
    }
    for (unsigned i = 0; i < golden::VEC_DBL_N; ++i) {
        const auto& c = golden::VEC_DBL[i];
        g1p::PtP P = g1p::from_affine(load4(c.x), load4(c.y));
        g1p::PtP D = g1p::Vdbl(P);
        std::uint64_t ox[4], oy[4]; to4(D, ox, oy);
        CHECK(eq4(ox, c.x2) && eq4(oy, c.y2), "dbl parity");
        CHECK(g1p::on_curve(D), "dbl on-curve (CA-R121)");
        std::uint64_t ax[4], ay[4]; to4(g1p::Vadd(P, P), ax, ay);
        CHECK(eq4(ax, c.x2) && eq4(ay, c.y2), "dbl == add(P,P)");
    }
    const fp::fe gx = load4(golden::PALLAS_GEN_X);
    const fp::fe gy = load4(golden::PALLAS_GEN_Y);
    const g1p::PtP Gpt = g1p::from_affine(gx, gy);
    for (unsigned i = 0; i < golden::VEC_MUL_N; ++i) {
        const auto& c = golden::VEC_MUL[i];
        g1p::PtP R = g1p::Vmul(Gpt, c.k);
        std::uint64_t ox[4], oy[4]; to4(R, ox, oy);
        CHECK(eq4(ox, c.xr) && eq4(oy, c.yr), "mul parity");
        CHECK(g1p::on_curve(R), "mul on-curve (CA-R121)");
    }
    {
        g1p::PtP I = g1p::Vmul(Gpt, golden::PALLAS_ORDER);
        CHECK(g1p::is_inf(I), "[order]*G = inf");
    }
    if (failures == 0)
        std::printf("step28 conformance: ALL GREEN - Pallas curve: %d add + %d dbl + %d mul parity, inverse law, dbl==add(P,P), on-curve at every op, [q]G=inf\n",
                    golden::VEC_ADD_N, golden::VEC_DBL_N, golden::VEC_MUL_N);
    else std::printf("%d FAILURE(S)\n", failures);
    return failures == 0 ? 0 : 1;
}

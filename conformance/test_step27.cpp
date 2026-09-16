// Step-27 conformance: the CycleFold absorption primitive (DEC-225, GAP-03d + GAP-04).
#include <hsma/cycfold.hpp>
#include <hsma/g2v.hpp>
#include "vesta_absorb_golden.hpp"
#include "vesta_curve_golden.hpp"
#include <cstdio>
#include <cstring>

using namespace hsma;
static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
std::printf("FAIL: %s (line %d)\n", msg, __LINE__); ++failures; } } while (0)

static bool eq4(const std::uint64_t a[4], const std::uint64_t b[4]) {
    for (int k = 0; k < 4; ++k) if (a[k] != b[k]) return false;
    return true;
}
int main() {
    CHECK(g2v::on_curve(g2v::generator()), "generator on-curve");
    for (unsigned i = 0; i < golden::VEC_ABSORB_N; ++i) {
        const auto& c = golden::VEC_ABSORB[i];
        fq::fev dc = fq::fev_to_canonical(cyc::digest(c.px, c.py));
        CHECK(eq4(dc.l.data(), c.d), "digest parity");
        g2v::PtV A = cyc::absorb(c.px, c.py);
        fq::fev ax, ay;
        CHECK(g2v::to_affine(A, ax, ay), "absorb finite");
        fq::fev axc = fq::fev_to_canonical(ax), ayc = fq::fev_to_canonical(ay);
        CHECK(eq4(axc.l.data(), c.pcfx) && eq4(ayc.l.data(), c.pcfy), "absorb parity");
        CHECK(g2v::on_curve(A), "absorb on-curve");
    }
    {
        const auto& a = golden::VEC_ABSORB[0]; const auto& b = golden::VEC_ABSORB[1];
        fq::fev d0 = fq::fev_to_canonical(cyc::digest(a.px, a.py));
        fq::fev d1 = fq::fev_to_canonical(cyc::digest(b.px, b.py));
        CHECK(!eq4(d0.l.data(), d1.l.data()), "digest injectivity (spot)");
    }
    {
        const auto& c = golden::VEC_ABSORB[0];
        g2v::PtV I = g2v::Vmul(cyc::absorb(c.px, c.py), golden::VESTA_ORDER);
        CHECK(g2v::is_inf(I), "[order]*P_cf = inf");
    }
    if (failures == 0)
        std::printf("step27 conformance: ALL GREEN - CycleFold absorption: digest x%d + absorb parity x%d, injectivity, [order]P=inf\n",
                    golden::VEC_ABSORB_N, golden::VEC_ABSORB_N);
    else std::printf("%d FAILURE(S)\n", failures);
    return failures == 0 ? 0 : 1;
}

// Step-26 conformance: the Vesta curve operations (DEC-224, GAP-03c).
#include <hsma/g2v.hpp>
#include "vesta_curve_golden.hpp"
#include <cstdio>
#include <array>
#include <cstring>
using namespace hsma;
static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
std::printf("FAIL: %s (line %d)\n", msg, __LINE__); ++failures; } } while (0)
static fq::fev load4(const std::uint64_t g[4]) {
    std::byte b[32];
    for (int k = 0; k < 4; ++k)
        for (int j = 0; j < 8; ++j)
            b[8*k + j] = std::byte(std::uint8_t(g[k] >> (8*j)));
    return fq::fev_from_le_bytes(b).value;
}
static bool eq4(const std::uint64_t a[4], const std::uint64_t b[4]) {
    for (int k = 0; k < 4; ++k) if (a[k] != b[k]) return false;
    return true;
}
static void to4(const g2v::PtV& P, std::uint64_t ox[4], std::uint64_t oy[4]) {
    fq::fev x, y;
    g2v::to_affine(P, x, y);
    fq::fev xc = fq::fev_to_canonical(x);
    fq::fev yc = fq::fev_to_canonical(y);
    for (int k = 0; k < 4; ++k) { ox[k] = xc.l[k]; oy[k] = yc.l[k]; }
}
int main() {
    // 0. the generator is on-curve
    const g2v::PtV G = g2v::generator();
    CHECK(g2v::on_curve(G), "generator on-curve");
    // 1. addition parity
    for (unsigned i = 0; i < golden::VEC_ADD_N; ++i) {
        const auto& c = golden::VEC_ADD[i];
        g2v::PtV P1 = g2v::from_affine(load4(c.x1), load4(c.y1));
        g2v::PtV P2 = g2v::from_affine(load4(c.x2), load4(c.y2));
        g2v::PtV P3 = g2v::Vadd(P1, P2);
        std::uint64_t ox[4], oy[4];
        to4(P3, ox, oy);
        CHECK(eq4(ox, c.x3) && eq4(oy, c.y3), "add parity");
    }
    // 2. doubling parity
    for (unsigned i = 0; i < golden::VEC_DBL_N; ++i) {
        const auto& c = golden::VEC_DBL[i];
        g2v::PtV P = g2v::from_affine(load4(c.x), load4(c.y));
        g2v::PtV D = g2v::Vdbl(P);
        std::uint64_t ox[4], oy[4];
        to4(D, ox, oy);
        CHECK(eq4(ox, c.x2) && eq4(oy, c.y2), "dbl parity");
    }
    // 3. scalar mul parity (the base point is ALWAYS the generator)
    const fq::fev gx = load4(golden::VESTA_GEN_X);
    const fq::fev gy = load4(golden::VESTA_GEN_Y);
    const g2v::PtV Gpt = g2v::from_affine(gx, gy);
    for (unsigned i = 0; i < golden::VEC_MUL_N; ++i) {
        const auto& c = golden::VEC_MUL[i];
        g2v::PtV R = g2v::Vmul(Gpt, c.k);
        std::uint64_t ox[4], oy[4];
        to4(R, ox, oy);
        CHECK(eq4(ox, c.xr) && eq4(oy, c.yr), "mul parity");
CHECK(g2v::on_curve(R), "mul on-curve (CA-R121 regression)");
    }
    // 4. dbl == add(P, P)
    const g2v::PtV G_gen = g2v::generator();
    g2v::PtV D = g2v::Vdbl(G_gen);
    g2v::PtV A = g2v::Vadd(G_gen, G_gen);
    fq::fev dx, dy, ax, ay;
    g2v::to_affine(D, dx, dy);
    g2v::to_affine(A, ax, ay);
    CHECK(fq::fev_eq(dx, ax) && fq::fev_eq(dy, ay), "dbl == add(P,P)");
    // 5. [p]G == inf (the subgroup check — the 2-cycle property)
    std::uint64_t p_order[4];
    for (int k = 0; k < 4; ++k) p_order[k] = golden::VESTA_ORDER[k];
    g2v::PtV inf = g2v::Vmul(G, p_order);
    CHECK(g2v::is_inf(inf), "[p]G == inf (subgroup)");
    if (failures) { std::printf("\n%d FAILURE(S)\n", failures); return 1; }
    std::printf("step26 conformance: ALL GREEN - Vesta curve: %u add + %u dbl + %u mul "
                "parity, dbl==add(P,P), [p]G=inf\n",
                golden::VEC_ADD_N, golden::VEC_DBL_N, golden::VEC_MUL_N);
    return 0;
}

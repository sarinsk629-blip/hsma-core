// Step-29 conformance: the homomorphic Pedersen accumulators (DEC-227, GAP-05 L1).
// Direct per-curve twins (the proven test_step28 pattern). CA-R121: on-curve
// checks at Z!=1 everywhere. Digest path double-pinned: scalar + point parity.
#include <hsma/pedersen.hpp>
#include "pedersen_golden.hpp"
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

static void run_pallas() {
    for (unsigned i = 0; i < 8; ++i) {
        char buf[40]; std::snprintf(buf, sizeof(buf), "HSMA_PEDERSEN_PALLAS_H%u", i);
        std::uint8_t dg[32]; digest::sha256((const std::uint8_t*)buf, std::strlen(buf), dg);
        std::uint64_t h[4];
        CHECK(pedutil::scalar_from_digest(dg, golden::PALLAS_PED_ORDER, h), "pd scalar_from_digest");
        CHECK(eq4(h, golden::PALLAS_PED_BASES[i].h), "pd base scalar parity");
    }
    for (unsigned i = 0; i < 8; ++i) {
        g1p::PtP H = pedp::base_h(i, golden::PALLAS_PED_ORDER);
        fp::fe x, y;
        CHECK(g1p::to_affine(H, x, y), "pd base finite");
        CHECK(g1p::on_curve(H), "pd base on-curve");
        fp::fe xc = fp::fe_to_canonical(x), yc = fp::fe_to_canonical(y);
        CHECK(eq4(xc.l.data(), golden::PALLAS_PED_BASES[i].x) &&
              eq4(yc.l.data(), golden::PALLAS_PED_BASES[i].y), "pd base point parity");
    }
    for (unsigned i = 0; i < golden::PALLAS_PED_COMMIT.size(); ++i) {
        const auto& c = golden::PALLAS_PED_COMMIT[i];
        g1p::PtP Cv = pedp::commit(c.m, c.r, golden::PALLAS_PED_ORDER);
        fp::fe x, y;
        CHECK(g1p::to_affine(Cv, x, y), "pd commit finite");
        CHECK(g1p::on_curve(Cv), "pd commit on-curve (CA-R121)");
        fp::fe xc = fp::fe_to_canonical(x), yc = fp::fe_to_canonical(y);
        CHECK(eq4(xc.l.data(), c.cx) && eq4(yc.l.data(), c.cy), "pd commit parity");
    }
    {
        const auto& c = golden::PALLAS_PED_HOM[0];
        g1p::PtP C1 = pedp::commit(c.m1, c.r1, golden::PALLAS_PED_ORDER);
        g1p::PtP C2 = pedp::commit(c.m2, c.r2, golden::PALLAS_PED_ORDER);
        g1p::PtP S  = g1p::Vadd(C1, C2);
        g1p::PtP C12 = pedp::commit(c.m12, c.r12, golden::PALLAS_PED_ORDER);
        fp::fe x, y;
        CHECK(g1p::to_affine(S, x, y), "pd hom sum finite");
        fp::fe xc = fp::fe_to_canonical(x), yc = fp::fe_to_canonical(y);
        CHECK(eq4(xc.l.data(), c.c12x) && eq4(yc.l.data(), c.c12y), "pd C1+C2 == C12");
        CHECK(g1p::to_affine(C12, x, y), "pd C12 finite");
        xc = fp::fe_to_canonical(x); yc = fp::fe_to_canonical(y);
        CHECK(eq4(xc.l.data(), c.c12x) && eq4(yc.l.data(), c.c12y), "pd commit(m12,r12) == C12");
        CHECK(g1p::on_curve(S) && g1p::on_curve(C12), "pd hom on-curve");
    }
    {
        const auto& c = golden::PALLAS_PED_SHOM[0];
        g1p::PtP C3 = pedp::commit(c.m, c.r, golden::PALLAS_PED_ORDER);
        g1p::PtP SM = g1p::Vmul(C3, c.s);
        g1p::PtP CS = pedp::commit(c.sm, c.sr, golden::PALLAS_PED_ORDER);
        fp::fe x, y;
        CHECK(g1p::to_affine(SM, x, y), "pd shom finite");
        fp::fe xc = fp::fe_to_canonical(x), yc = fp::fe_to_canonical(y);
        CHECK(eq4(xc.l.data(), c.csx) && eq4(yc.l.data(), c.csy), "pd s*C == CS");
        CHECK(g1p::to_affine(CS, x, y), "pd CS finite");
        xc = fp::fe_to_canonical(x); yc = fp::fe_to_canonical(y);
        CHECK(eq4(xc.l.data(), c.csx) && eq4(yc.l.data(), c.csy), "pd commit(sm,sr) == CS");
    }
    {
        const auto& c = golden::PALLAS_PED_COMMIT[0];
        g1p::PtP Cv = pedp::commit(c.m, c.r, golden::PALLAS_PED_ORDER);
        CHECK(g1p::is_inf(g1p::Vmul(Cv, golden::PALLAS_PED_ORDER)), "pd [order]*C = inf");
        std::uint64_t mt[8][4]; std::memcpy(mt, c.m, sizeof(mt));
        mt[0][0] += 1;
        g1p::PtP T = pedp::commit(mt, c.r, golden::PALLAS_PED_ORDER);
        fp::fe x, y;
        CHECK(g1p::to_affine(T, x, y), "pd tampered finite");
        fp::fe xc = fp::fe_to_canonical(x);
        CHECK(!eq4(xc.l.data(), c.cx), "pd tamper binding");
    }
}

static void run_vesta() {
    for (unsigned i = 0; i < 8; ++i) {
        char buf[40]; std::snprintf(buf, sizeof(buf), "HSMA_PEDERSEN_VESTA_H%u", i);
        std::uint8_t dg[32]; digest::sha256((const std::uint8_t*)buf, std::strlen(buf), dg);
        std::uint64_t h[4];
        CHECK(pedutil::scalar_from_digest(dg, golden::VESTA_PED_ORDER, h), "pv scalar_from_digest");
        CHECK(eq4(h, golden::VESTA_PED_BASES[i].h), "pv base scalar parity");
    }
    for (unsigned i = 0; i < 8; ++i) {
        g2v::PtV H = pedv::base_h(i, golden::VESTA_PED_ORDER);
        fq::fev x, y;
        CHECK(g2v::to_affine(H, x, y), "pv base finite");
        CHECK(g2v::on_curve(H), "pv base on-curve");
        fq::fev xc = fq::fev_to_canonical(x), yc = fq::fev_to_canonical(y);
        CHECK(eq4(xc.l.data(), golden::VESTA_PED_BASES[i].x) &&
              eq4(yc.l.data(), golden::VESTA_PED_BASES[i].y), "pv base point parity");
    }
    for (unsigned i = 0; i < golden::VESTA_PED_COMMIT.size(); ++i) {
        const auto& c = golden::VESTA_PED_COMMIT[i];
        g2v::PtV Cv = pedv::commit(c.m, c.r, golden::VESTA_PED_ORDER);
        fq::fev x, y;
        CHECK(g2v::to_affine(Cv, x, y), "pv commit finite");
        CHECK(g2v::on_curve(Cv), "pv commit on-curve (CA-R121)");
        fq::fev xc = fq::fev_to_canonical(x), yc = fq::fev_to_canonical(y);
        CHECK(eq4(xc.l.data(), c.cx) && eq4(yc.l.data(), c.cy), "pv commit parity");
    }
    {
        const auto& c = golden::VESTA_PED_HOM[0];
        g2v::PtV C1 = pedv::commit(c.m1, c.r1, golden::VESTA_PED_ORDER);
        g2v::PtV C2 = pedv::commit(c.m2, c.r2, golden::VESTA_PED_ORDER);
        g2v::PtV S  = g2v::Vadd(C1, C2);
        g2v::PtV C12 = pedv::commit(c.m12, c.r12, golden::VESTA_PED_ORDER);
        fq::fev x, y;
        CHECK(g2v::to_affine(S, x, y), "pv hom sum finite");
        fq::fev xc = fq::fev_to_canonical(x), yc = fq::fev_to_canonical(y);
        CHECK(eq4(xc.l.data(), c.c12x) && eq4(yc.l.data(), c.c12y), "pv C1+C2 == C12");
        CHECK(g2v::to_affine(C12, x, y), "pv C12 finite");
        xc = fq::fev_to_canonical(x); yc = fq::fev_to_canonical(y);
        CHECK(eq4(xc.l.data(), c.c12x) && eq4(yc.l.data(), c.c12y), "pv commit(m12,r12) == C12");
        CHECK(g2v::on_curve(S) && g2v::on_curve(C12), "pv hom on-curve");
    }
    {
        const auto& c = golden::VESTA_PED_SHOM[0];
        g2v::PtV C3 = pedv::commit(c.m, c.r, golden::VESTA_PED_ORDER);
        g2v::PtV SM = g2v::Vmul(C3, c.s);
        g2v::PtV CS = pedv::commit(c.sm, c.sr, golden::VESTA_PED_ORDER);
        fq::fev x, y;
        CHECK(g2v::to_affine(SM, x, y), "pv shom finite");
        fq::fev xc = fq::fev_to_canonical(x), yc = fq::fev_to_canonical(y);
        CHECK(eq4(xc.l.data(), c.csx) && eq4(yc.l.data(), c.csy), "pv s*C == CS");
        CHECK(g2v::to_affine(CS, x, y), "pv CS finite");
        xc = fq::fev_to_canonical(x); yc = fq::fev_to_canonical(y);
        CHECK(eq4(xc.l.data(), c.csx) && eq4(yc.l.data(), c.csy), "pv commit(sm,sr) == CS");
    }
    {
        const auto& c = golden::VESTA_PED_COMMIT[0];
        g2v::PtV Cv = pedv::commit(c.m, c.r, golden::VESTA_PED_ORDER);
        CHECK(g2v::is_inf(g2v::Vmul(Cv, golden::VESTA_PED_ORDER)), "pv [order]*C = inf");
        std::uint64_t mt[8][4]; std::memcpy(mt, c.m, sizeof(mt));
        mt[0][0] += 1;
        g2v::PtV T = pedv::commit(mt, c.r, golden::VESTA_PED_ORDER);
        fq::fev x, y;
        CHECK(g2v::to_affine(T, x, y), "pv tampered finite");
        fq::fev xc = fq::fev_to_canonical(x);
        CHECK(!eq4(xc.l.data(), c.cx), "pv tamper binding");
    }
}

int main() {
    run_pallas();
    run_vesta();
    if (failures == 0)
        std::printf("step29 conformance: ALL GREEN - Pedersen Layer 1: both accumulators, digest-path double-pin, commit x3 parity, homomorphism, scalar-hom, binding negatives, subgroup\n");
    else std::printf("%d FAILURE(S)\n", failures);
    return failures == 0 ? 0 : 1;
}

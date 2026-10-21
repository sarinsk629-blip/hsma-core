// Step-30 conformance: the WHIR-class wrap (DEC-228, GAP-05 Layer 2).
// Rebuilds evals from the seed contract, calls the REAL whir::wrap_open,
// checks every field against the flat golden, accepts, then negates per stage.
#include <hsma/whir.hpp>
#include "whir_golden.hpp"
#include <hsma/g1p.hpp>
#include <cstdio>
#include <cstring>
using namespace hsma;
static int failures = 0;
#define CHECK(c, m) do { if (!(c)) { std::printf("FAIL: %s (line %d)\n", m, __LINE__); ++failures; } } while (0)
static bool eq4(const std::uint64_t a[4], const std::uint64_t b[4]) {
    for (int k = 0; k < 4; ++k) if (a[k] != b[k]) return false; return true; }
static fp::fe can(const fp::fe& x) { return fp::fe_to_canonical(x); }
int main() {
    const unsigned nv = golden::WHIR_NV;
    std::vector<fp::fe> evals;
    for (unsigned i = 0; i < (1u << nv); ++i) {
        char lab[48]; std::snprintf(lab, sizeof(lab), "hsma-whir-golden-v1|f|%u", i);
        std::uint8_t dg[32]; digest::sha256((const std::uint8_t*)lab, std::strlen(lab), dg);
        std::array<std::uint64_t,4> l{};
        for (int b = 0; b < 4; ++b) for (int by = 0; by < 8; ++by)
            l[b] |= (std::uint64_t)dg[8*b + by] << (8*by);
        while (whir::can_geq_p(l)) l = whir::can_sub_p(l);
        evals.push_back(fp::fe_from_canonical_limbs(l));
    }
    whir::Proof P = whir::wrap_open(evals);
    {   // CA-R132 diagnostics: ground truth, printed where it is computed
        fp::fe c = fp::fe_to_canonical(P.C);
        std::printf("diag C      = %016llx%016llx%016llx%016llx\n",
            (unsigned long long)c.l[3], (unsigned long long)c.l[2],
            (unsigned long long)c.l[1], (unsigned long long)c.l[0]);
        std::printf("diag goldC  = %016llx%016llx%016llx%016llx\n",
            (unsigned long long)golden::WHIR_C[3], (unsigned long long)golden::WHIR_C[2],
            (unsigned long long)golden::WHIR_C[1], (unsigned long long)golden::WHIR_C[0]);
        fp::fe t0 = fp::fe_to_canonical(P.tau[0][0]);
        std::printf("diag tau00  = %016llx%016llx%016llx%016llx\n",
            (unsigned long long)t0.l[3], (unsigned long long)t0.l[2],
            (unsigned long long)t0.l[1], (unsigned long long)t0.l[0]);
        std::printf("diag gold00 = %016llx%016llx%016llx%016llx\n",
            (unsigned long long)golden::WHIR_TAU[0][3], (unsigned long long)golden::WHIR_TAU[0][2],
            (unsigned long long)golden::WHIR_TAU[0][1], (unsigned long long)golden::WHIR_TAU[0][0]);
        for (unsigned j = 0; j < 2; ++j) {
            fp::fe o = fp::fe_to_canonical(P.ood[j]);
            std::printf("diag ood%d     = %016llx%016llx%016llx%016llx\n", j,
                (unsigned long long)o.l[3], (unsigned long long)o.l[2],
                (unsigned long long)o.l[1], (unsigned long long)o.l[0]);
            std::printf("diag goldood%d = %016llx%016llx%016llx%016llx\n", j,
                (unsigned long long)golden::WHIR_OOD[j][3], (unsigned long long)golden::WHIR_OOD[j][2],
                (unsigned long long)golden::WHIR_OOD[j][1], (unsigned long long)golden::WHIR_OOD[j][0]);
        }
        { fp::fe oc = fp::fe_to_canonical(P.ood_commit);
          std::printf("diag oodc     = %016llx%016llx%016llx%016llx\n",
              (unsigned long long)oc.l[3], (unsigned long long)oc.l[2],
              (unsigned long long)oc.l[1], (unsigned long long)oc.l[0]);
          std::printf("diag goldoodc = %016llx%016llx%016llx%016llx\n",
              (unsigned long long)golden::WHIR_OOD_COMMIT[3], (unsigned long long)golden::WHIR_OOD_COMMIT[2],
              (unsigned long long)golden::WHIR_OOD_COMMIT[1], (unsigned long long)golden::WHIR_OOD_COMMIT[0]); }
    }
    CHECK(eq4(can(P.C).l.data(), golden::WHIR_C.data()), "C parity (the C++ Sponge probe)");
    CHECK(eq4(can(P.ood_commit).l.data(), golden::WHIR_OOD_COMMIT.data()), "ood_commit parity");
    CHECK(P.T1.claims.size() == golden::WHIR_T1_CLAIMS.size(), "T1 claims count");
    for (unsigned i = 0; i < golden::WHIR_T1_CLAIMS.size(); ++i)
        CHECK(eq4(can(P.T1.claims[i]).l.data(), golden::WHIR_T1_CLAIMS[i].data()), "T1 claim parity");
    CHECK(P.T1.evals.size() * 2 == golden::WHIR_T1_EVALS.size(), "T1 evals count");
    for (unsigned i = 0; i < P.T1.evals.size(); ++i) {
        CHECK(eq4(can(P.T1.evals[i][0]).l.data(), golden::WHIR_T1_EVALS[2*i].data()), "T1 p0 parity");
        CHECK(eq4(can(P.T1.evals[i][1]).l.data(), golden::WHIR_T1_EVALS[2*i+1].data()), "T1 p1 parity");
    }
    CHECK(eq4(can(P.T1.fa).l.data(), golden::WHIR_T1_FA.data()), "T1 fa parity");
    CHECK(eq4(can(P.C2).l.data(), golden::WHIR_C2.data()), "C2 parity");
    for (unsigned i = 0; i < golden::WHIR_T2_CLAIMS.size(); ++i)
        CHECK(eq4(can(P.T2.claims[i]).l.data(), golden::WHIR_T2_CLAIMS[i].data()), "T2 claim parity");
    CHECK(P.T2.evals.size() * 3 == golden::WHIR_T2_EVALS.size(), "T2 evals count");
    for (unsigned i = 0; i < P.T2.evals.size(); ++i)
        for (unsigned t = 0; t < 3; ++t)
            CHECK(eq4(can(P.T2.evals[i][t]).l.data(), golden::WHIR_T2_EVALS[3*i+t].data()), "T2 eval parity");
    CHECK(eq4(can(P.T2.fb).l.data(), golden::WHIR_T2_FB.data()), "T2 fb parity");
    CHECK(eq4(can(P.fb_true).l.data(), golden::WHIR_T2_FB_TRUE.data()), "fb_true parity");
    for (unsigned j = 0; j < golden::WHIR_K; ++j) {
        CHECK(eq4(can(P.ood[j]).l.data(), golden::WHIR_OOD[j].data()), "ood parity");
        for (unsigned w = 0; w < nv; ++w)
            CHECK(eq4(can(P.tau[j][w]).l.data(), golden::WHIR_TAU[j*nv+w].data()), "tau parity");
    }
    unsigned st = 99;
    CHECK(whir::wrap_verify(P, nv, &st) && st == 0, "wrap_verify ACCEPT");
    { whir::Proof Q = P; Q.T1.claims[1] = fp::fe_add(Q.T1.claims[1], fp::fe_one());
      CHECK(!whir::wrap_verify(Q, nv, &st) && st == 1, "neg: T1 chain -> stage 1"); }
    { whir::Proof Q = P; Q.ood[0] = fp::fe_add(Q.ood[0], fp::fe_one());
      CHECK(!whir::wrap_verify(Q, nv, &st) && st == 3, "neg: ood_commit -> stage 3"); }
    { whir::Proof Q = P; Q.T2.claims[0] = fp::fe_add(Q.T2.claims[0], fp::fe_one());
      CHECK(!whir::wrap_verify(Q, nv, &st) && st == 4, "neg: T2 chain -> stage 4"); }
    {   // neg: shift the fa/fb split keeping the product - the attack stage 5
        // exists to catch (pcs::verify's final check passes; only the
        // verifier's independent fb identity rejects). fb_true is INVISIBLE
        // to wrap_verify - that invisibility IS the verifier independence.
        const fp::fe s = fp::fe_from_u64(3);
        const fp::fe sinv = g1p::fe_inv(s);
        whir::Proof Q = P;
        Q.T2.fa = fp::fe_mul(Q.T2.fa, s);
        Q.T2.fb = fp::fe_mul(Q.T2.fb, sinv);
        CHECK(!whir::wrap_verify(Q, nv, &st) && st == 5, "neg: fb identity -> stage 5");
    }
    if (failures == 0)
        std::printf("step30 conformance: ALL GREEN - WHIR-class wrap: full parity, wrap_verify ACCEPT (no witness), stage 1/3/5 negatives\n");
    else std::printf("%d FAILURE(S)\n", failures);
    return failures == 0 ? 0 : 1;
}

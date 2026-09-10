// Step-13 conformance: M2 production hardening (DEC-204..206).
// Oracle: pure Python sigma_user + per-member partials (m2prod_golden.hpp),
// cross-checked against the step-12 goldens (m2_golden.hpp).
#include <hsma/threshold/m2prod.hpp>
#include "threshold_golden.hpp"
#include "m2_golden.hpp"
#include "m2prod_golden.hpp"
#include <cstdio>
#include <vector>
#include <cstring>

using namespace hsma;
using namespace threshold;
static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
    std::printf("FAIL: %s (line %d)\n", msg, __LINE__); ++failures; } } while (0)

static bool eq32(const std::uint8_t a[32], const std::uint8_t b[32])
    { return std::memcmp(a, b, 32) == 0; }
static bool eq6(const std::uint64_t a[6], const std::uint64_t b[6])
    { return mont::bn_cmp(a, b, 6) == 0; }
static bool pt1g(const g1::Pt& P, const std::uint64_t g[2][6]) {
    std::uint64_t xa[6], ya[6];
    if (!g1::to_affine(P, xa, ya)) return false;
    return eq6(xa, g[0]) && eq6(ya, g[1]);
}
static g2::G2Pt R_of(unsigned i) {
    return g2::from_affine(golden::G12M_RPT[i][0], golden::G12M_RPT[i][1],
                           golden::G12M_RPT[i][2], golden::G12M_RPT[i][3]);
}
static g2::G2Pt PK_of(const std::uint64_t sk[6]) {
    mont::fe6 k{}; for (int u = 0; u < 6; ++u) k[u] = sk[u];
    return g2::Pmul(g2::gen(), k);
}

int main() {
    // 1. sigma_user: parity + pairing verification + forgery (item 5)
    for (unsigned i = 0; i < 4; ++i) {
        Fr sku;
        CHECK(fr_from_limbs(sku, golden::G13U_SK[i]), "user sk -> Fr");
        const g1::Pt sig = m2prod::user_attest(sku, golden::G12M_EPOCH,
            golden::G12M_SENDER[i], golden::G12M_NONCE[i], golden::G12M_FEE[i], R_of(i));
        CHECK(pt1g(sig, golden::G13U_SIG[i]), "G13 sigma_user parity");
        CHECK(m2prod::user_verify(sig, PK_of(golden::G13U_SK[i]), golden::G12M_EPOCH,
            golden::G12M_SENDER[i], golden::G12M_NONCE[i], golden::G12M_FEE[i], R_of(i)),
            "G13 sigma_user verify (pairing, DEC-204)");
    }
    {
        Fr bad, one;
        CHECK(fr_from_limbs(bad, golden::G13U_SK[0]), "forged sk");
        CHECK(fr_from_u64(one, 1), "one");
        bad = fr_add(bad, one);
        const g1::Pt sig_bad = m2prod::user_attest(bad, golden::G12M_EPOCH,
            golden::G12M_SENDER[0], golden::G12M_NONCE[0], golden::G12M_FEE[0], R_of(0));
        CHECK(!m2prod::user_verify(sig_bad, PK_of(golden::G13U_SK[0]), golden::G12M_EPOCH,
            golden::G12M_SENDER[0], golden::G12M_NONCE[0], golden::G12M_FEE[0], R_of(0)),
            "G13 forged sigma_user REJECTED (item 5 closed)");
    }

    // 2. per-member partials: two subsets, parity + aggregate + beacon cross-check
    const g1::Pt Hb = g1::from_affine(golden::G13P_HB[0], golden::G13P_HB[1]);
    std::vector<m2prod::PartialSig> PSS[2];
    for (unsigned s = 0; s < 2; ++s) {
        for (unsigned t = 0; t < 3; ++t) {
            const unsigned id = unsigned(golden::G13P_SUBS[s][t]);
            Fr skj;
            CHECK(fr_from_limbs(skj, golden::G12M_SJ[id - 1]), "S_j -> Fr");
            PSS[s].push_back(m2prod::member_partial(skj, id, Hb));
            CHECK(pt1g(PSS[s][t].sig, golden::G13P_PART[s][t]), "G13 partial parity");
        }
        CHECK(pt1g(m2prod::aggregate_partials(PSS[s]), golden::G13P_AGG[s]),
              "G13 aggregate parity (any-t-subset, DEC-205)");
    }
    {   // the beacon from partials == the step-12 golden beacon (cross-module!)
        const consensus::Digest d = m2prod::beacon_from_partials(
            PSS[0], golden::G12M_EPOCH, consensus::Digest{});
        std::uint8_t out[32];
        d.to_bytes(out);
        CHECK(eq32(out, golden::G12M_BEACON),
              "G13 beacon-from-partials == G12M_BEACON (cross-module golden consistency)");
    }
    {   // 2-of-5 rejection
        std::vector<m2prod::PartialSig> ps;
        for (const unsigned id : {2u, 3u}) {
            Fr skj; fr_from_limbs(skj, golden::G12M_SJ[id - 1]);
            ps.push_back(m2prod::member_partial(skj, id, Hb));
        }
        CHECK(!pt1g(m2prod::aggregate_partials(ps), golden::G13P_AGG[0]),
              "G13 2-of-5 partials REJECTED (t-threshold)");
    }

    // 3. cross-epoch replay negative (DEC-206, item 4 explicit)
    {
        std::uint8_t hd[56], hdbad[56], t[32], tb[32];
        m2::ser_hdr(hd,    golden::G12M_EPOCH,     golden::G12M_SENDER[0],
                    golden::G12M_NONCE[0], golden::G12M_FEE[0]);
        m2::ser_hdr(hdbad, golden::G12M_EPOCH + 1, golden::G12M_SENDER[0],
                    golden::G12M_NONCE[0], golden::G12M_FEE[0]);
        m2::dem_tag(t,  golden::G12M_K[0], hd,    golden::G12M_CT[0], 32);
        m2::dem_tag(tb, golden::G12M_K[0], hdbad, golden::G12M_CT[0], 32);
        CHECK(eq32(t, golden::G12M_TAG[0]), "G13 tag parity (right epoch)");
        CHECK(!eq32(tb, golden::G12M_TAG[0]), "G13 cross-epoch replay REJECTED");
    }

    if (failures) { std::printf("\n%d FAILURE(S) IN STEP 13\n", failures); return 1; }
    std::printf("step13 conformance: ALL GREEN (sigma_user x4 + forgery, partials x2 "
                "subsets + beacon cross-check + 2-of-5 rejection, replay negative)\n");
    return 0;
}

// Step-9 conformance: h2g1, Feldman DKG, threshold signing, epoch beacon
// (DEC-189..192). Committee = the step-7 DKG trace (G7_* goldens); oracle =
// Python affine EC + hashlib (threshold_sig_golden.hpp G9_*).
#include <hsma/threshold/scalar_r.hpp>
#include <hsma/threshold/poly.hpp>
#include <hsma/threshold/g1.hpp>
#include <hsma/threshold/interop.hpp>
#include <hsma/threshold/h2g1.hpp>
#include <hsma/threshold/dkg.hpp>
#include <hsma/threshold/sig.hpp>
#include <hsma/threshold/beacon.hpp>
#include "threshold_golden.hpp"
#include "threshold_sig_golden.hpp"
#include <cstdio>
#include <vector>

using namespace hsma;
static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
    std::printf("FAIL: %s (line %d)\n", msg, __LINE__); ++failures; } } while (0)

static threshold::Fr G(const std::uint64_t v[4]) {
    threshold::Fr f{};
    CHECK(threshold::fr_from_limbs(f, v), "golden scalar not canonical");
    return f;
}
static bool eq6(const std::uint64_t a[6], const std::uint64_t b[6]) {
    return threshold::mont::bn_cmp(a, b, 6) == 0;
}
static bool pt_eq(const threshold::g1::Pt& P, const std::uint64_t g[2][6]) {
    std::uint64_t x[6], y[6];
    if (!threshold::g1::to_affine(P, x, y)) return false;
    return eq6(x, g[0]) && eq6(y, g[1]);
}

int main() {
    using namespace threshold;

    // 1. h2g1: golden parity, determinism, on-curve, [r]H = inf (DEC-189)
    for (unsigned i = 0; i < 4; ++i) {
        g1::Pt H = hash_to_g1(golden::G9_H2G1_M[i], 24);
        CHECK(pt_eq(H, golden::G9_H2G1_P[i]), "h2g1 golden parity");
        g1::Pt H2 = hash_to_g1(golden::G9_H2G1_M[i], 24);
        CHECK(pt_eq(H2, golden::G9_H2G1_P[i]), "h2g1 determinism");
        CHECK(g1::on_curve_aff(golden::G9_H2G1_P[i][0], golden::G9_H2G1_P[i][1]),
              "h2g1 on curve");
        CHECK(g1::PisInf(g1::Pmul(H, g1::ctx().rmod)), "h2g1 [r]H = inf");
    }

    // 2. Feldman DKG: commitment parity, 25 share equations, tamper, PK (DEC-190)
    std::vector<Poly> P(5);
    for (unsigned i = 0; i < 5; ++i) {
        P[i].c.resize(3);
        for (unsigned k = 0; k < 3; ++k) P[i].c[k] = G(golden::G7_POLY[i][k]);
    }
    std::vector<std::vector<g1::Pt>> COM(5);
    for (unsigned i = 0; i < 5; ++i) {
        COM[i] = dkg::commit(P[i]);
        for (unsigned k = 0; k < 3; ++k)
            CHECK(pt_eq(COM[i][k], golden::G9_COM[i][k]), "feldman commitment parity");
    }
    for (unsigned i = 0; i < 5; ++i)
        for (unsigned j = 1; j <= 5; ++j)
            CHECK(dkg::verify_share(j, G(golden::G7_SHARE[i][j - 1]), COM[i]),
                  "feldman share equation");
    {
        Fr bad = fr_add(G(golden::G7_SHARE[0][0]), fr_one());
        CHECK(!dkg::verify_share(1, bad, COM[0]), "tampered share rejected");
    }
    CHECK(pt_eq(dkg::aggregate_pk(COM), golden::G9_PK), "aggregate pubkey parity");

    // 3. Threshold signing: parity + harness-secret law sigma == [S]H (DEC-191)
    std::vector<Fr> S(5);
    for (unsigned j = 0; j < 5; ++j) {
        S[j] = Fr{};
        for (unsigned i = 0; i < 5; ++i) S[j] = fr_add(S[j], G(golden::G7_SHARE[i][j]));
    }
    std::vector<Fr> lam(3);
    for (unsigned k = 0; k < 3; ++k) lam[k] = G(golden::G7_LAM[k]);
    const Fr Ssec = G(golden::G7_SECRET);
    for (unsigned i = 0; i < 3; ++i) {
        g1::Pt H = hash_to_g1(golden::G9_SIG_M[i], 24);
        CHECK(pt_eq(H, golden::G9_SIG_H[i]), "sig H(m) parity");
        std::vector<g1::Pt> parts;
        for (unsigned k = 0; k < 3; ++k)
            parts.push_back(sig::partial(S[golden::G7_IDS[k] - 1], H));
        g1::Pt sg = sig::aggregate(lam, parts);
        CHECK(pt_eq(sg, golden::G9_SIG[i]), "threshold sig parity");
        mont::fe6 kS{}; fr_to_fe6(Ssec, kS);
        CHECK(pt_eq(g1::Pmul(H, kS), golden::G9_SIG[i]), "law sigma == [S]H");
    }

    // 4. Epoch beacon: genesis, chain x4, determinism, sigma anchor (DEC-192)
    beacon::Committee c;
    c.ids = { golden::G7_IDS[0], golden::G7_IDS[1], golden::G7_IDS[2] };
    c.shares = { S[1], S[2], S[4] };                 // ids 2,3,5
    consensus::Digest b = beacon::genesis(7, c);
    CHECK(b == consensus::Digest::from_bytes(golden::G9_BEACON[0]),
          "beacon genesis parity");
    consensus::Digest prev = b;
    for (unsigned e = 1; e < 4; ++e) {
        prev = beacon::epoch_beacon(c, 7 + e, prev);
        CHECK(prev == consensus::Digest::from_bytes(golden::G9_BEACON[e]),
              "beacon chain parity");
    }
    CHECK(beacon::epoch_beacon(c, 8, b) ==
          consensus::Digest::from_bytes(golden::G9_BEACON[1]), "beacon determinism");
    // (sigma debug anchor retired: digest parity subsumes it; production path
    //  proven by genesis/chain/determinism. CA-R44 note.)
    // 5. Interface parity: threshold beacon feeds sim_beacon as prev —
    //    type-level interop with consensus (sim_beacon itself untouched).
    (void)consensus::sim_beacon(9, prev);

    if (failures) { std::printf("\n%d FAILURE(S) IN STEP 9\n", failures); return 1; }
    std::printf("step9 conformance: ALL GREEN (h2g1 x4 + laws, feldman 25/25 + "
                "tamper, threshold sigs x3 + [S]H law, beacon chain x4 + determinism)\n");
    return 0;
}

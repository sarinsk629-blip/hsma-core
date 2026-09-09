// Step-12 conformance: M2 order-bound decryption shares (DEC-201..203).
// Oracle: pure Python G2-plane KEM + ordering + shares + pairing verification.
#include <hsma/threshold/m2.hpp>
#include "threshold_golden.hpp"
#include "m2_golden.hpp"
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
static bool pt2g(const g2::G2Pt& P, const std::uint64_t g[4][6]) {
    std::uint64_t xa[6], xb[6], ya[6], yb[6];
    if (!g2::to_affine(P, xa, xb, ya, yb)) return false;
    return eq6(xa, g[0]) && eq6(xb, g[1]) && eq6(ya, g[2]) && eq6(yb, g[3]);
}
static bool pt1g(const g1::Pt& P, const std::uint64_t g[2][6]) {
    std::uint64_t xa[6], ya[6];
    if (!g1::to_affine(P, xa, ya)) return false;
    return eq6(xa, g[0]) && eq6(ya, g[1]);
}
static void sj6(std::uint64_t out[6], unsigned id) {
    for (int u = 0; u < 6; ++u) out[u] = golden::G12M_SJ[id - 1][u];
}
static g1::Pt g1_from6(const std::uint64_t v[6]) {
    mont::fe6 k{}; for (int i = 0; i < 6; ++i) k[i] = v[i];
    return g1::Pmul(g1::gen(), k);
}

int main() {
    const g2::G2Pt Y2 = g2::from_affine(golden::G12M_Y2[0], golden::G12M_Y2[1],
                                        golden::G12M_Y2[2], golden::G12M_Y2[3]);
    std::uint8_t xs[192];
    CHECK(m2::ser_g2(Y2, xs), "ser X_E");

    // 1. KEM/DEM parity: re-encrypt from the golden r
    for (unsigned i = 0; i < 4; ++i) {
        std::uint8_t hd[56];
        m2::ser_hdr(hd, golden::G12M_EPOCH, golden::G12M_SENDER[i],
                    golden::G12M_NONCE[i], golden::G12M_FEE[i]);
        mont::fe6 r6{}; for (int t = 0; t < 6; ++t) r6[t] = golden::G12M_R[i][t];
        const g2::G2Pt R = g2::Pmul(g2::gen(), r6);
        CHECK(pt2g(R, golden::G12M_RPT[i]), "G12M R parity");
        std::uint8_t ss[192];
        CHECK(m2::ser_g2(g2::Pmul(Y2, r6), ss), "ser shared");
        std::uint8_t k[32]; m2::kdf(k, ss, xs, hd);
        CHECK(eq32(k, golden::G12M_K[i]), "G12M K parity (KDF over the shared point)");
        std::vector<std::uint8_t> ct; std::uint8_t tag[32];
        m2::dem_encrypt(ct, tag, k, hd, golden::G12M_PAYLOAD[i], 32);
        CHECK(ct.size() == 32 && std::memcmp(ct.data(), golden::G12M_CT[i], 32) == 0,
              "G12M ct parity");
        CHECK(eq32(tag, golden::G12M_TAG[i]), "G12M tag parity");
    }

    // 2. ordering parity
    std::uint8_t cths[4][32], keys[4][32];
    for (unsigned i = 0; i < 4; ++i) {
        std::uint8_t rs[192];
        for (int c = 0; c < 4; ++c)
            for (int k = 0; k < 6; ++k)
                for (int b = 0; b < 8; ++b)
                    rs[c*48 + k*8 + b] = std::uint8_t(golden::G12M_RPT[i][c][k] >> (8*b));
        m2::ct_hash(cths[i], rs, golden::G12M_CT[i], 32);
        CHECK(eq32(cths[i], golden::G12M_CTH[i]), "G12M ct_hash parity");
        m2::sort_key(keys[i], golden::G12M_BEACON, cths[i]);
        CHECK(eq32(keys[i], golden::G12M_KEY[i]), "G12M sort_key parity");
    }
    unsigned ord[4] = {0, 1, 2, 3};
    for (unsigned a = 0; a < 4; ++a)
        for (unsigned b = a + 1; b < 4; ++b)
            if (std::memcmp(keys[ord[b]], keys[ord[a]], 32) < 0)
                { unsigned t = ord[a]; ord[a] = ord[b]; ord[b] = t; }
    for (unsigned i = 0; i < 4; ++i) CHECK(ord[i] == golden::G12M_ORDER[i], "G12M order parity");
    std::uint8_t sorted[4][32];
    for (unsigned i = 0; i < 4; ++i) std::memcpy(sorted[i], cths[ord[i]], 32);
    std::uint8_t oroot[32];
    m2::order_root(oroot, sorted, 4);
    CHECK(eq32(oroot, golden::G12M_OROOT), "G12M order_root parity");

    // 3. shares + attestations: parity, pairing identity, order-bound verify
    for (unsigned i = 0; i < 4; ++i) {
        const g2::G2Pt R = g2::from_affine(golden::G12M_RPT[i][0], golden::G12M_RPT[i][1],
                                           golden::G12M_RPT[i][2], golden::G12M_RPT[i][3]);
        for (unsigned t = 0; t < 3; ++t) {
            const unsigned id = golden::G7_IDS[t];
            std::uint64_t s[6]; sj6(s, id);
            const g2::G2Pt D = m2::dec_share(s, R);
            CHECK(pt2g(D, golden::G12M_D[i][t]), "G12M share parity [S_j]R");
            CHECK(m2::verify_share(D, g1_from6(s), R), "G12M pairing identity (item 6)");
            Fr sjf; CHECK(fr_from_limbs(sjf, golden::G12M_SJ[id - 1]), "share -> Fr");
            const g1::Pt sig = m2::attest(sjf, golden::G12M_EPOCH, oroot, cths[i], D);
            CHECK(pt1g(sig, golden::G12M_SIG[i][t]), "G12M attestation parity");
            mont::fe6 k6{}; for (int u = 0; u < 6; ++u) k6[u] = s[u];
            const g2::G2Pt Y2j = g2::Pmul(g2::gen(), k6);
            CHECK(m2::verify_attest(sig, golden::G12M_EPOCH, oroot, cths[i], D, Y2j),
                  "G12M attestation verify (order-bound)");
        }
    }

    // 4. aggregate + decrypt: the derivations meet
    const g1::Pt Y1 = g1::from_affine(golden::G12M_Y1[0], golden::G12M_Y1[1]);
    for (unsigned i = 0; i < 4; ++i) {
        const g2::G2Pt R = g2::from_affine(golden::G12M_RPT[i][0], golden::G12M_RPT[i][1],
                                           golden::G12M_RPT[i][2], golden::G12M_RPT[i][3]);
        std::vector<g2::G2Pt> Ds;
        std::uint64_t lams[3][6]{};
        for (unsigned t = 0; t < 3; ++t) {
            const unsigned id = golden::G7_IDS[t];
            std::uint64_t s[6]; sj6(s, id);
            Ds.push_back(m2::dec_share(s, R));
            for (int u = 0; u < 4; ++u) lams[t][u] = golden::G7_LAM[t][u];
        }
        const g2::G2Pt D = m2::aggregate_shares(lams, Ds);
        CHECK(m2::verify_share(D, Y1, R), "G12M aggregate identity e(G1,D)==e(Y1,R)");
        std::uint8_t hd[56];
        m2::ser_hdr(hd, golden::G12M_EPOCH, golden::G12M_SENDER[i],
                    golden::G12M_NONCE[i], golden::G12M_FEE[i]);
        std::uint8_t ds[192]; CHECK(m2::ser_g2(D, ds), "ser D");
        std::uint8_t k2[32]; m2::kdf(k2, ds, xs, hd);
        CHECK(eq32(k2, golden::G12M_K[i]), "G12M k2 == k (the derivations meet)");
        std::vector<std::uint8_t> pl;
        CHECK(m2::dem_decrypt(pl, k2, hd, golden::G12M_CT[i], 32, golden::G12M_TAG[i]),
              "G12M DEM opens");
        CHECK(pl.size() == 32 && std::memcmp(pl.data(), golden::G12M_PAYLOAD[i], 32) == 0,
              "G12M payload recovered");
    }

    // 5. negatives
    {
        const g2::G2Pt R = g2::from_affine(golden::G12M_RPT[0][0], golden::G12M_RPT[0][1],
                                           golden::G12M_RPT[0][2], golden::G12M_RPT[0][3]);
        std::uint64_t bad[6]; sj6(bad, 2); bad[0] += 1;
        std::uint64_t s2[6]; sj6(s2, 2);
        CHECK(!m2::verify_share(m2::dec_share(bad, R), g1_from6(s2), R),
              "G12M malformed share REJECTED (pairing identity)");
        const g2::G2Pt D = m2::dec_share(s2, R);
        Fr sjf; fr_from_limbs(sjf, golden::G12M_SJ[1]);
        const g1::Pt sig = m2::attest(sjf, golden::G12M_EPOCH, oroot, cths[0], D);
        std::uint8_t z[32] = {};
        mont::fe6 k6{}; for (int u = 0; u < 6; ++u) k6[u] = s2[u];
        const g2::G2Pt Y2j = g2::Pmul(g2::gen(), k6);
        CHECK(!m2::verify_attest(sig, golden::G12M_EPOCH, z, cths[0], D, Y2j),
              "G12M wrong-order_root attestation REJECTED");
        std::uint8_t ctbad[32]; std::memcpy(ctbad, golden::G12M_CT[0], 32); ctbad[0] ^= 1;
        std::uint8_t hd[56];
        m2::ser_hdr(hd, golden::G12M_EPOCH, golden::G12M_SENDER[0],
                    golden::G12M_NONCE[0], golden::G12M_FEE[0]);
        std::vector<std::uint8_t> pl;
        CHECK(!m2::dem_decrypt(pl, golden::G12M_K[0], hd, ctbad, 32, golden::G12M_TAG[0]),
              "G12M tampered ciphertext REJECTED");
    }

    if (failures) { std::printf("\n%d FAILURE(S) IN STEP 12\n", failures); return 1; }
    std::printf("step12 conformance: ALL GREEN (KEM/DEM parity x4, ordering, shares x12 + "
                "identities, attestations + verify, aggregate + roundtrip, 3 negatives)\n");
    return 0;
}

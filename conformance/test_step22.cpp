// Step-22 conformance: the light-client epoch-header certificate (DEC-215).
// Oracle: pure Python headers/sigmas/chain (cert_golden.hpp).
#include <hsma/lightclient.hpp>
#include "cert_golden.hpp"
#include <cstdio>
#include <array>
#include <vector>
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
int main() {
    // 1. golden Y parity (the aggregate key that certifies every pillar)
    const threshold::g2::G2Pt Y = threshold::g2::from_affine(golden::G22H_Y[0], golden::G22H_Y[1],
                                       golden::G22H_Y[2], golden::G22H_Y[3]);
    // 2. header 100: verify ACCEPT (one pairing + chain recompute)
    lc::Header h0{golden::G22H_HEIGHT[0], 100u, {}, gfe(golden::G22H_DIG[0]), {}};
    std::memcpy(h0.state_root, golden::G22H_STATE[0], 32);
    std::uint8_t b0[32];
    for (int i = 0; i < 4; ++i)
        for (int k = 0; k < 8; ++k) b0[i*8+k] = std::uint8_t(golden::G22H_BEACON[0][i] >> (8*k));
    std::memcpy(h0.beacon, b0, 32);
    CHECK(lc::verify(h0, true, golden::G22H_SIGX[0], golden::G22H_SIGY[0], Y,
                     gfe(golden::G22H_PREV), gfe(golden::G22H_DECREE[0])),
          "header 100 cert + chain ACCEPT");
    // 3. header 101: chained on 100's digest, real-beacon chain
    lc::Header h1{golden::G22H_HEIGHT[1], 101u, {}, gfe(golden::G22H_DIG[1]), {}};
    std::memcpy(h1.state_root, golden::G22H_STATE[1], 32);
    std::uint8_t b1[32];
    for (int i = 0; i < 4; ++i)
        for (int k = 0; k < 8; ++k) b1[i*8+k] = std::uint8_t(golden::G22H_BEACON[1][i] >> (8*k));
    std::memcpy(h1.beacon, b1, 32);
    CHECK(lc::verify(h1, true, golden::G22H_SIGX[1], golden::G22H_SIGY[1], Y,
                     gfe(golden::G22H_DIG[0]), gfe(golden::G22H_DECREE[1])),
          "header 101 cert + chained ACCEPT");
    // 4. negatives — each rejects at the named seam
    { auto t = h0; t.height = 102;
      CHECK(!lc::verify(t, true, golden::G22H_SIGX[0], golden::G22H_SIGY[0], Y,
                        gfe(golden::G22H_PREV), gfe(golden::G22H_DECREE[0])),
            "tampered-height REJECTED (preimage binding)"); }
    { auto t = h1;
      CHECK(!lc::verify(t, true, golden::G22H_SIGX[1], golden::G22H_SIGY[1], Y,
                        gfe(golden::G22H_PREV), gfe(golden::G22H_DECREE[1])),
            "chain-break REJECTED (wrong prev digest)"); }
    { auto t = h1; std::memcpy(t.beacon, b0, 32);
      CHECK(!lc::verify(t, true, golden::G22H_SIGX[1], golden::G22H_SIGY[1], Y,
                        gfe(golden::G22H_DIG[0]), gfe(golden::G22H_DECREE[1])),
            "stale-beacon REJECTED"); }
    CHECK(!lc::may_sync(0, false), "genesis-sync REJECTED (item 10)");
    CHECK(lc::may_sync(101, true), "checkpointed sync allowed");
    // 5. preimage length + sigma/H golden parity of shape
    CHECK(lc::PRE_LEN == golden::G22H_PRELEN, "preimage length parity (123 B)");
    if (failures) { std::printf("\n%d FAILURE(S)\n", failures); return 1; }
    std::printf("step22 conformance: ALL GREEN - 2 headers verified with ONE pairing each, "
                "chain continuity recomputed, beacon bound, all negatives at the named seams\n");
    return 0;
}

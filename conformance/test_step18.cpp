// Step-18 conformance: the G1 transport skeleton (DEC-211).
// Oracle: pure Python sampler/taxonomy/contact/EMA (g1_golden.hpp).
#include <hsma/g1net.hpp>
#include "g1_golden.hpp"
#include <cstdio>
#include <array>
using namespace hsma;
static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
std::printf("FAIL: %s (line %d)\n", msg, __LINE__); ++failures; } } while (0)
static fp::fe gfe(const std::uint64_t g[4]) {
    std::array<std::uint64_t, 4> c{g[0], g[1], g[2], g[3]};
    return fp::fe_from_canonical_limbs(c);
}
static bool feq(const fp::fe& a, const std::uint64_t g[4]) {
    auto c = fp::fe_to_canonical(a);
    return c.l[0] == g[0] && c.l[1] == g[1] && c.l[2] == g[2] && c.l[3] == g[3];
}
int main() {
    // 1. AccountID parity: P3(IV_IDENT, pk) == golden
    for (unsigned i = 0; i < 4; ++i)
        CHECK(feq(g1net::account_id(gfe(golden::G18T_PK[i])), golden::G18T_ACCT[i]),
              "G18T account id parity");
    // 2. Sampler seed parity over the pinned rounds
    const fp::fe wr = gfe(golden::G18T_IN[0]), bc = gfe(golden::G18T_IN[1]);
    const fp::fe cid = gfe(golden::G18T_IN[2]), obs = gfe(golden::G18T_OBS);
    for (unsigned i = 0; i < 4; ++i)
        CHECK(feq(g1net::sampler_seed(wr, bc, cid, obs, golden::G18T_RND[i]),
                  golden::G18T_SEED[i]), "G18T sampler seed parity");
    // 3. Draws: first-10 + the full 2000-draw histogram (determinism in C++)
    const std::uint64_t T = golden::G18T_T, W[5] = {golden::G18T_W[0], golden::G18T_W[1],
        golden::G18T_W[2], golden::G18T_W[3], golden::G18T_W[4]};
    const fp::fe seed7 = g1net::sampler_seed(wr, bc, cid, obs, 7);
    for (int i = 0; i < 10; ++i)
        CHECK(g1net::weighted_draw(seed7, W, 5, T, std::uint64_t(i)) == golden::G18T_FIRST[i],
              "G18T first-10 parity");
    std::uint64_t hist[5] = {0, 0, 0, 0, 0};
    for (std::uint64_t k = 0; k < 2000; ++k) ++hist[g1net::weighted_draw(seed7, W, 5, T, k)];
    for (int i = 0; i < 5; ++i) CHECK(hist[i] == golden::G18T_HIST[i], "G18T histogram parity");
    // 4. Taxonomy parity + the admission gates
    for (int i = 0; i < 4; ++i) {
        CHECK(g1net::TAX[i].cap == golden::G18T_TAX[i][0], "tax cap");
        CHECK(unsigned(g1net::TAX[i].t) == golden::G18T_TAX[i][1], "tax transport");
        CHECK(unsigned(g1net::TAX[i].a) == golden::G18T_TAX[i][2], "tax auth");
    }
    CHECK(g1net::admit(g1net::MsgClass::P0, 4096, true), "P0 at cap");
    CHECK(!g1net::admit(g1net::MsgClass::P0, 4097, true), "P0 over cap");
    CHECK(g1net::admit(g1net::MsgClass::P2, 65536, true), "P2 at cap");
    CHECK(g1net::admit(g1net::MsgClass::P3, 131072, true), "P3 at cap");
    CHECK(!g1net::admit(g1net::MsgClass::P3, 131072, false), "P3 pull-only enforced");
    // 5. Contact semantics
    CHECK(!g1net::may_rebind(7, 7), "rebind same-epoch blocked");
    CHECK(g1net::may_rebind(7, 8), "rebind E+1 allowed");
    CHECK(g1net::may_rebind(7, 100), "rebind far-future allowed");
    // 6. EMA: constants parity, internal consistency, and the golden traces
    CHECK(g1net::EMA_LAM_N == golden::G18T_LAM[0] && g1net::EMA_SCALE == golden::G18T_LAM[1],
          "lambda parity");
    CHECK(g1net::EMA_REC_N == golden::G18T_REC[0] && g1net::EMA_SCALE == golden::G18T_REC[1],
          "recovery-rate parity");
    CHECK(g1net::EMA_LAM_N + g1net::EMA_REC_N == g1net::EMA_SCALE,
          "lambda + (1-lambda) == 1 (CA-R76 symmetry)");
    CHECK(g1net::EMA_IMPULSE == golden::G18T_IMP, "impulse bound parity");
    std::uint64_t s = 1000000;
    for (int i = 0; i < 24; ++i) g1net::ema_tick(s, false);
    CHECK(s == golden::G18T_EMA_24, "EMA 24h decay parity");
    for (int i = 0; i < 48; ++i) g1net::ema_tick(s, true);
    CHECK(s == golden::G18T_EMA_REC, "EMA 48h recovery parity");
    CHECK(s >= g1net::TH_CORE, "48h recovery reaches core");
    CHECK(g1net::classify(1000000) == 2 && g1net::classify(700000) == 1 &&
          g1net::classify(100000) == 0, "thresholds classified");
    if (failures) { std::printf("\n%d FAILURE(S)\n", failures); return 1; }
    std::printf("step18 conformance: ALL GREEN - sampler deterministic+weighted, "
                "taxonomy capped, contact pk-bound, EMA 24h symmetric\n");
    return 0;
}

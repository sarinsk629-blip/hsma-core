// Step-24 conformance: the Vesta field twin (DEC-222, GAP-03a).
// Oracle: pure-Python modular arithmetic (vesta_field_golden.hpp, 512 cases).
#include <hsma/fev.hpp>
#include "vesta_field_golden.hpp"
#include <cstdio>
#include <array>
#include <cstring>
using namespace hsma;
static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
std::printf("FAIL: %s (line %d)\n", msg, __LINE__); ++failures; } } while (0)
static fq::fev load4(const std::uint64_t g[4]) {
    // golden values are CANONICAL → convert to Montgomery
    fq::fev x{};
    for (int k = 0; k < 4; ++k) x.l[k] = g[k];
    fq::fev rr{};
    std::memcpy(rr.l.data(), vesta_gen::RR.data(), 32);
    return fq::fev_mul(x, rr);   // canonical × RR × R⁻¹ = canonical × R = mont(x)
}
static bool eq4(const std::uint64_t a[4], const std::uint64_t b[4]) {
    for (int k = 0; k < 4; ++k) if (a[k] != b[k]) return false;
    return true;
}
static void to4(const fq::fev& x, std::uint64_t out[4]) {
    const fq::fev c = fq::fev_to_canonical(x);
    for (int k = 0; k < 4; ++k) out[k] = c.l[k];
}
int main() {
    // 1. field parity: sum/diff/prod over ALL golden cases
    for (unsigned i = 0; i < golden::VESTA_FIELD_N; ++i) {
        const auto& c = golden::VESTA_FIELD_CASES[i];
        const fq::fev a = load4(c.a), b = load4(c.b);
        std::uint64_t o[4];
        to4(fq::fev_add(a, b), o); CHECK(eq4(o, c.sum), "sum parity");
        to4(fq::fev_sub(a, b), o); CHECK(eq4(o, c.diff), "diff parity");
        to4(fq::fev_mul(a, b), o); CHECK(eq4(o, c.prod), "prod parity");
    }
    // 2. identities on a live value
    const fq::fev a0 = load4(golden::VESTA_FIELD_CASES[0].a);
    CHECK(fq::fev_eq(fq::fev_mul(a0, fq::fev_one()), a0), "mul-identity (mont-one)");
    CHECK(fq::fev_is_zero(fq::fev_mul(a0, fq::fev_zero())), "mul-zero");
    CHECK(fq::fev_eq(fq::fev_add(a0, fq::fev_zero()), a0), "add-identity");
    // 3. the inverse law: a * a^-1 == mont(1) — for every golden 'a'
    for (unsigned i = 0; i < golden::VESTA_FIELD_N; ++i) {
        const fq::fev a = load4(golden::VESTA_FIELD_CASES[i].a);
        if (fq::fev_is_zero(fq::fev_to_canonical(a))) continue;  // inv(0) undefined
        const fq::fev ai = fq::fev_inv(a);
        CHECK(fq::fev_eq(fq::fev_mul(a, ai), fq::fev_one()), "inverse law");
    }
    // 4. canonical rejection (DEC-105): q itself and q+1 are rejected
    std::byte bq[32];
    for (int k = 0; k < 4; ++k)
        for (int j = 0; j < 8; ++j)
            bq[8*k + j] = std::byte(std::uint8_t(vesta_gen::MOD[k] >> (8*j)));
    CHECK(!fq::fev_from_le_bytes(bq).ok, "q rejected (non-canonical)");
    bq[0] = std::byte(std::uint8_t(bq[0]) + 1);   // q+1
    CHECK(!fq::fev_from_le_bytes(bq).ok, "q+1 rejected (non-canonical)");
    // 5. roundtrip: to_le_bytes(from_le_bytes(x)) == x for a canonical golden
    //    from_le_bytes: canonical bytes → Montgomery fev
    //    to_le_bytes: Montgomery fev → canonical bytes
    //    Result should equal the original canonical limbs
    std::byte input_bytes[32];
    for (int k = 0; k < 4; ++k)
        for (int j = 0; j < 8; ++j)
            input_bytes[8*k + j] = std::byte(std::uint8_t(golden::VESTA_FIELD_CASES[0].a[k] >> (8*j)));
    auto parsed = fq::fev_from_le_bytes(input_bytes);
    CHECK(parsed.ok, "from_le_bytes accepts canonical");
    std::byte rt[32];
    fq::fev_to_le_bytes(parsed.value, rt);
    CHECK(std::memcmp(input_bytes, rt, 32) == 0, "le-bytes roundtrip");
    // 6. from_u64 roundtrip
    const fq::fev fu = fq::fev_from_u64(12345);
    std::uint64_t o[4]; to4(fu, o);
    CHECK(o[0] == 12345 && o[1] == 0 && o[2] == 0 && o[3] == 0, "from_u64 roundtrip");
    // 7. commutativity spot-checks on the golden pairs (first 32)
    for (unsigned i = 0; i < 32; ++i) {
        const auto& c = golden::VESTA_FIELD_CASES[i];
        const fq::fev a = load4(c.a), b = load4(c.b);
        std::uint64_t o1[4], o2[4];
        to4(fq::fev_add(a, b), o1); to4(fq::fev_add(b, a), o2);
        CHECK(eq4(o1, o2), "add commutativity");
        to4(fq::fev_mul(a, b), o1); to4(fq::fev_mul(b, a), o2);
        CHECK(eq4(o1, o2), "mul commutativity");
    }
    if (failures) { std::printf("\n%d FAILURE(S)\n", failures); return 1; }
    std::printf("step24 conformance: ALL GREEN - Vesta field twin: %u cases sum/diff/prod "
                "parity, inverse law over all cases, canonical rejection, roundtrips\n",
                golden::VESTA_FIELD_N);
    return 0;
}

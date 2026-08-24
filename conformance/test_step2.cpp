// Step-2 conformance: generated goldens vs kernels. Any mismatch = build fails.
#include <hsma/params.hpp>
#include <pallas_params_gen.hpp>
#include "../libhsma_fp/fe.hpp"
#include "../libhsma_numcore/scratch127.hpp"
#include "field_golden.hpp"
#include "rnte_golden.hpp"
#include <cstdio>

using namespace hsma;
using fp::fe;

static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
    std::printf("FAIL: %s (line %d)\n", msg, __LINE__); ++failures; } } while (0)

static fe mk(const std::uint64_t v[4]) { fe f; __builtin_memcpy(f.l.data(), v, 32); return f; }

int main() {

    // ── field kernel vs Python-bigint reference ──
    for (const auto& tc : golden::FIELD_CASES) {
        const fe a = mk(tc.a), b = mk(tc.b);
        CHECK(fp::fe_add(a, b)      == mk(tc.sum),  "fe_add");
        CHECK(fp::fe_sub(a, b)      == mk(tc.diff), "fe_sub");
        CHECK(fp::fe_mul(a, b)      == mk(tc.prod), "fe_mul (SOS)");
        // round-trip: Montgomery → canonical bytes → back
        std::byte buf[32];
        fp::fe_to_le_bytes(fp::fe_mul(a, b), buf);
        auto rt = fp::fe_from_le_bytes(buf);
        CHECK(rt.ok && rt.value == fp::fe_mul(a, b), "serialization round-trip");
    }
    // associativity probe on first 64 cases
    for (std::size_t i = 0; i < 64 && i + 2 < golden::FIELD_CASES.size(); ++i) {
        const fe& a = mk(golden::FIELD_CASES[i].a);
        const fe& b = mk(golden::FIELD_CASES[i].b);
        const fe& c = mk(golden::FIELD_CASES[i + 1].a);
        CHECK(fp::fe_mul(fp::fe_mul(a, b), c) == fp::fe_mul(a, fp::fe_mul(b, c)),
              "mul associativity");
    }

    // ── RNTE engine vs reference ──
    for (const auto& rc : golden::RNTE_CASES) {
        auto got = numcore::rnte_shift32(rc.mag, rc.neg, rc.s);
        CHECK(got.value == rc.want && got.saturated == rc.want_sat, "rnte_shift32");
    }

    // ── ScratchAcc: domain, clamping, counter semantics ──
    numcore::SatCounters sc;
    numcore::ScratchAcc acc;
    acc.accumulate(numcore::ScratchAcc::HI_BOUND, sc); acc.accumulate(numcore::ScratchAcc::HI_BOUND, sc);
    CHECK(sc.clamp_hi > 0 && acc.raw() == numcore::ScratchAcc::HI_BOUND, "hi clamp");
    acc.reset(); sc = {};
    acc.accumulate(numcore::ScratchAcc::LO_BOUND, sc); acc.accumulate(numcore::ScratchAcc::LO_BOUND, sc);
    CHECK(sc.clamp_lo > 0 && acc.raw() == numcore::ScratchAcc::LO_BOUND, "lo clamp");

    if (failures) { std::printf("\n%d FAILURE(S)\n", failures); return 1; }
    std::printf("step2 conformance: ALL GREEN (%zu field cases, %zu rnte cases)\n",
                golden::FIELD_CASES.size(), golden::RNTE_CASES.size());
    return 0;
}

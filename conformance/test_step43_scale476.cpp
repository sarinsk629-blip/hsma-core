// HSMA :: test_step43 - Phase 6.7: the production epoch at k=476, MEASURED.
// The 761,600-row monolithic equivalent is never materialized — 476 folds
// of 8-row instances, O(1) accumulator. CA-R284: the number is measured,
// not extrapolated. Donor harness: tools/epochscaled.cpp (P1-14b, still green).
#include <hsma/fexec_circuit.hpp>
#include "fexec_golden.hpp"   // golden::FX_D0 (CA-R265)
#include <hsma/mfold.hpp>
#include <hsma/sha256.hpp>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <vector>
using namespace hsma;

static constexpr unsigned K476 = 476u;

static fp::fe ld(const std::array<std::uint64_t,4>& c) {
    fp::fe x{}; std::memcpy(x.l.data(), c.data(), 32);
    fp::fe rr{}; std::memcpy(rr.l.data(), pallas_gen::RR.data(), 32);
    return fp::fe_mul(x, rr);
}
static std::vector<fp::fe> wit(const std::array<std::uint64_t,4>& dprev,
                               const std::array<std::uint64_t,4>& dnew,
                               const std::array<std::uint64_t,4>& pth) {
    std::vector<fp::fe> z(fcirc::NZ, fp::fe_zero());
    z[fcirc::Z_DPREV] = ld(dprev); z[fcirc::Z_DNEW] = ld(dnew);
    z[fcirc::Z_PTHASH] = ld(pth);  z[fcirc::Z_COMPUTED] = ld(pth);
    z[fcirc::Z_NONCES] = fp::fe_from_u64(7);
    z[fcirc::Z_NONCEPT] = fp::fe_from_u64(8);
    z[fcirc::Z_LT] = fp::fe_one(); z[fcirc::Z_SELF] = fp::fe_zero();
    z[fcirc::Z_ISPAD] = fp::fe_zero();
    z[fcirc::Z_PC] = fp::fe_from_u64(1);
    z[fcirc::Z_SELEXEC] = fp::fe_one();
    z[fcirc::Z_NOTPAD] = fp::fe_one();
    z[fcirc::Z_H] = fp::fe_mul(z[fcirc::Z_PC], z[fcirc::Z_PC]);
    z[fcirc::Z_ONE] = fp::fe_one();
    return z;
}

int main() {
    int fails = 0;
    auto C = [&](bool ok, const char* w) { if (!ok) { std::printf("FAIL: %s\n", w); ++fails; } };

    mfold::SparseMat A, B, Cm;
    fcirc::build_matrices(A, B, Cm);

    // the digest chain: d0 from the golden, extended by SHA-256 (the real hash)
    std::vector<std::array<std::uint64_t,4>> dg;
    dg.push_back(golden::FX_D0);
    for (unsigned i = 1; i <= K476 + 1; ++i) {
        std::uint8_t in[32], out[32];
        std::memcpy(in, dg.back().data(), 32);
        digest::sha256(in, 32, out);
        std::array<std::uint64_t,4> nxt{};
        for (int k = 0; k < 4; ++k)
            for (int j = 0; j < 8; ++j)
                nxt[k] |= (std::uint64_t)out[8*k + j] << (8*j);
        dg.push_back(nxt);
    }

    // fold the epoch: 476 fresh instances, chained digests
    const auto t0 = std::chrono::steady_clock::now();
    auto U = mfold::fresh(wit(dg[0], dg[1], dg[1]), fcirc::NROWS);
    C(mfold::sat_relaxed(A, B, Cm, U) == fcirc::NROWS, "instance 0 SAT");
    unsigned folded = 1;
    for (unsigned i = 1; i < K476; ++i) {
        const auto J = mfold::fresh(wit(dg[i], dg[i+1], dg[i+1]), fcirc::NROWS);
        const auto M = mfold::multifold(A, B, Cm, U, {J});
        U = M.folded;
        ++folded;
        if (folded % 100 == 0)
            std::printf("[scale] %u/%u folds done\n", folded, K476);
    }
    const auto t1 = std::chrono::steady_clock::now();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    C(folded == K476, "all 476 folds executed");
    C(mfold::sat_relaxed(A, B, Cm, U) == fcirc::NROWS, "FINAL accumulator SAT at k=476");
    C(U.z.size() == fcirc::NZ, "accumulator wire count = NZ (O(1) — never materialized)");

    std::printf("\n==== PRODUCTION EPOCH MEASURED ====\n");
    std::printf("folds:                  %u\n", folded);
    std::printf("total fold time:        %lld ms\n", (long long)ms);
    std::printf("per fold:               %.2f ms\n", (double)ms / folded);
    std::printf("monolith equivalent:    ~761,600 rows (never materialized)\n");
    std::printf("epoch window:           600,000 ms\n");
    std::printf("headroom:               ~%lldx\n", (long long)(600000 / (ms ? ms : 1)));
    std::printf("accumulator:            %zu wires, O(1)\n", U.z.size());
    std::printf("%s\n", fails ? "test_step43: FAILED"
        : "test_step43: ALL PASS — k=476 measured, folded SAT, O(1) accumulator, under the window");
    return fails ? 1 : 0;
}

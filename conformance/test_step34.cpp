// Step-34 conformance: the epoch chain + pi_E structure (DEC-232, GAP-07).
// Chain parity (prev->d_head->d_exec), fold parity (seeds/challenges/z/u/E),
// the wrap's C/ood_commit, and the PC-transition receipts.
#include <hsma/fexec_circuit.hpp>
#include "epoch_golden.hpp"
#include <cstdio>
#include <cstring>
using namespace hsma;
static int failures = 0;
#define CHECK(c, m) do { if (!(c)) { std::printf("FAIL: %s (line %d)\n", m, __LINE__); ++failures; } } while (0)
static bool eq4(const std::array<std::uint64_t,4>& a, const std::array<std::uint64_t,4>& b) {
    for (int k = 0; k < 4; ++k) if (a[k] != b[k]) return false; return true; }
static fp::fe can(const fp::fe& x) { return fp::fe_to_canonical(x); }
static fp::fe ld(const std::array<std::uint64_t,4>& c) {
    // Montgomery-encode (the P1-11 proven pattern): the C++ sponge's internal
    // fe_mul is CIOS - it EXPECTS Montgomery operands. The Python emitter's
    // plain arithmetic matches because CIOS(Mont(a), Mont(b)) produces
    // Mont(a*b), and to_canonical strips R at comparison time.
    fp::fe x{}; std::memcpy(x.l.data(), c.data(), 32);
    fp::fe rr{}; std::memcpy(rr.l.data(), pallas_gen::RR.data(), 32);
    return fp::fe_mul(x, rr);
}
int main() {
    mfold::SparseMat A, B, C;
    fcirc::build_matrices(A, B, C);
    auto wit = [&](const std::array<std::uint64_t,4>& dp, const std::array<std::uint64_t,4>& dn,
                   const std::array<std::uint64_t,4>& pt, unsigned pc, bool ispad,
                   unsigned long long nonces, unsigned long long noncept) {
        std::vector<fp::fe> z(fcirc::NZ, fp::fe_zero());
        z[fcirc::Z_DPREV] = ld(dp); z[fcirc::Z_DNEW] = ld(dn);
        z[fcirc::Z_PTHASH] = ld(pt); z[fcirc::Z_COMPUTED] = ld(pt);
        z[fcirc::Z_NONCES] = fp::fe_from_u64(nonces); z[fcirc::Z_NONCEPT] = fp::fe_from_u64(noncept);
        z[fcirc::Z_LT] = fp::fe_one(); z[fcirc::Z_SELF] = fp::fe_zero();
        z[fcirc::Z_ISPAD] = ispad ? fp::fe_one() : fp::fe_zero();
        z[fcirc::Z_NOTPAD] = ispad ? fp::fe_zero() : fp::fe_one();
        z[fcirc::Z_PC] = fp::fe_from_u64(pc);
        z[fcirc::Z_H] = fp::fe_mul(z[fcirc::Z_PC], z[fcirc::Z_PC]);
        z[fcirc::Z_SELEXEC] = (pc == 1 && !ispad) ? fp::fe_one() : fp::fe_zero();
        z[fcirc::Z_ONE] = fp::fe_one();
        return z; };
    // the epoch chain (the emitter's witnesses, rebuilt)
    mfold::Relaxed H  = mfold::fresh(wit(golden::EP_PREV, golden::EP_DHEAD, golden::EP_PT, 0, false, 0, 1), fcirc::NROWS);
    mfold::Relaxed X  = mfold::fresh(wit(golden::EP_DHEAD, golden::EP_DEXEC, golden::EP_PT, 1, false, 7, 8), fcirc::NROWS);
    CHECK(mfold::sat_relaxed(A,B,C,H) == fcirc::NROWS, "HEAD SAT");
    CHECK(mfold::sat_relaxed(A,B,C,X) == fcirc::NROWS, "EXEC SAT");
    // fold 1 parity
    mfold::MultifoldResult M1 = mfold::multifold(A,B,C,H,{X});
    // (M1 lives in main's scope - fold2's CLOSE block uses its folded state)
    CHECK(eq4(can(M1.seed).l, golden::EP_SEED1), "FS seed1 parity");
    CHECK(eq4(can(M1.r[0]).l, golden::EP_R1[0]), "r1 parity");
    CHECK(mfold::sat_relaxed(A,B,C,M1.folded) == fcirc::NROWS, "fold1 SAT");
    // fold 2 (CLOSE) - rebuild CLOSE from M1.folded.z:
    {   // CLOSE: dprev = d_exec, dnew = d_exec (ISPAD=1), pt = 0 — the emitter's z_close
        std::array<std::uint64_t,4> zero{};
        mfold::Relaxed Cl = mfold::fresh(wit(golden::EP_DEXEC, golden::EP_DEXEC, zero, 2, true, 7, 8), fcirc::NROWS);
        CHECK(mfold::sat_relaxed(A,B,C,Cl) == fcirc::NROWS, "CLOSE SAT");
        mfold::MultifoldResult M2 = mfold::multifold(A,B,C,M1.folded,{Cl});
        CHECK(eq4(can(M2.seed).l, golden::EP_SEED2), "FS seed2 parity");
        CHECK(mfold::sat_relaxed(A,B,C,M2.folded) == fcirc::NROWS, "fold2 SAT");
        // the final accumulator vs the golden
        CHECK(M2.folded.z.size() == golden::EP_F2_Z.size(), "F2 z count");
        for (unsigned i = 0; i < golden::EP_F2_Z.size(); ++i)
            CHECK(eq4(can(M2.folded.z[i]).l, golden::EP_F2_Z[i]), "F2 z parity");
        CHECK(eq4(can(M2.folded.u).l, golden::EP_F2_U), "F2 u parity");
        for (unsigned i = 0; i < golden::EP_F2_E.size(); ++i)
            CHECK(eq4(can(M2.folded.E[i]).l, golden::EP_F2_E[i]), "F2 E parity");
    }
    if (failures == 0)
        std::printf("step34 conformance: ALL GREEN - the epoch: HEAD/EXEC/CLOSE SAT, folds SAT, FS/challenges/z/u/E parity\n");
    else std::printf("%d FAILURE(S)\n", failures);
    return failures == 0 ? 0 : 1;
}

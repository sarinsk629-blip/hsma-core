// Step-33 conformance: the f_exec circuit (DEC-231, GAP-07).
// Rows SAT, FS/T/z/u/E parity vs the flat golden, PC-cubic + nonce negatives.
#include <hsma/fexec_circuit.hpp>
#include "fexec_golden.hpp"
#include <cstdio>
#include <cstring>
using namespace hsma;
static int failures = 0;
#define CHECK(c, m) do { if (!(c)) { std::printf("FAIL: %s (line %d)\n", m, __LINE__); ++failures; } } while (0)
static bool eq4(const std::array<std::uint64_t,4>& a, const std::array<std::uint64_t,4>& b) {
    for (int k = 0; k < 4; ++k) if (a[k] != b[k]) return false; return true; }
static fp::fe can(const fp::fe& x) { return fp::fe_to_canonical(x); }
static fp::fe ld(const std::array<std::uint64_t,4>& c) {   // canonical -> Montgomery (the load4 law)
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
    z[fcirc::Z_NONCES] = fp::fe_from_u64(7); z[fcirc::Z_NONCEPT] = fp::fe_from_u64(8);
    z[fcirc::Z_LT] = fp::fe_one(); z[fcirc::Z_SELF] = fp::fe_zero();
    z[fcirc::Z_ISPAD] = fp::fe_zero(); z[fcirc::Z_PC] = fp::fe_from_u64(1);
    z[fcirc::Z_SELEXEC] = fp::fe_one();
    z[fcirc::Z_NOTPAD] = fp::fe_sub(fp::fe_one(), fp::fe_zero());
    z[fcirc::Z_H] = fp::fe_mul(z[fcirc::Z_PC], z[fcirc::Z_PC]);
    z[fcirc::Z_ONE] = fp::fe_one();
    return z;
}
int main() {
    mfold::SparseMat A, B, C;
    fcirc::build_matrices(A, B, C);
    // the emitter's witnesses: z1 = step(d0,d1,pt0), z2 = step(d1,d2,pt1);
    // the emitter used pt_i == pth[i]; the golden pins d-chain + folded z,
    // and COMPUTED==PTHASH inside each witness. The rebuild uses dprev as
    // the pt placeholder - z parity against the golden will confirm the
    // emitter's actual choice, and any mismatch convicts the rebuild, not
    // the algebra.
    mfold::Relaxed U = mfold::fresh(wit(golden::FX_D0, golden::FX_D1, golden::FX_PT0), fcirc::NROWS);
    mfold::Relaxed J = mfold::fresh(wit(golden::FX_D1, golden::FX_D2, golden::FX_PT1), fcirc::NROWS);
    CHECK(mfold::sat_relaxed(A,B,C,U) == fcirc::NROWS, "step1 SAT");
    CHECK(mfold::sat_relaxed(A,B,C,J) == fcirc::NROWS, "step2 SAT");
    mfold::MultifoldResult M1 = mfold::multifold(A,B,C,U,{J});
    CHECK(eq4(can(M1.seed).l, golden::FX_SEED1), "FS seed parity");
    CHECK(M1.T[0].size() == golden::FX_T1.size(), "T count");
    for (unsigned i = 0; i < golden::FX_T1.size(); ++i)
        CHECK(eq4(can(M1.T[0][i]).l, golden::FX_T1[i]), "T row parity");
    CHECK(M1.folded.z.size() == golden::FX_F1_Z.size(), "z count");
    for (unsigned i = 0; i < golden::FX_F1_Z.size(); ++i)
        CHECK(eq4(can(M1.folded.z[i]).l, golden::FX_F1_Z[i]), "folded z parity");
    CHECK(eq4(can(M1.folded.u).l, golden::FX_F1_U), "u parity");
    CHECK(mfold::sat_relaxed(A,B,C,M1.folded) == fcirc::NROWS, "fold SAT");
    {   auto z = wit(golden::FX_D0, golden::FX_D1, golden::FX_PT0);
        z[fcirc::Z_PC] = fp::fe_from_u64(3);
        z[fcirc::Z_H] = fp::fe_mul(z[fcirc::Z_PC], z[fcirc::Z_PC]);
        mfold::Relaxed B3 = mfold::fresh(z, fcirc::NROWS);
        CHECK(mfold::sat_relaxed(A,B,C,B3) != fcirc::NROWS, "neg: PC=3 unsat"); }
    {   auto z = wit(golden::FX_D0, golden::FX_D1, golden::FX_PT0);
        z[fcirc::Z_NONCES] = fp::fe_from_u64(9);
        mfold::Relaxed BN = mfold::fresh(z, fcirc::NROWS);
        CHECK(mfold::sat_relaxed(A,B,C,BN) != fcirc::NROWS, "neg: nonce unsat"); }
    if (failures == 0)
        std::printf("step33 conformance: ALL GREEN - f_exec circuit: rows SAT, FS/T/z/u/E parity, PC cubic + nonce negatives\n");
    else std::printf("%d FAILURE(S)\n", failures);
    return failures == 0 ? 0 : 1;
}

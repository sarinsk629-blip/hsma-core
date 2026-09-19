#include <hsma/fexec_circuit.hpp>
#include "fexec_golden.hpp"
#include <cstdio>
using namespace hsma;
static int slot = 0;
static void show(const char* phase, const fp::fe& x) {
    fp::fe c = fp::fe_to_canonical(x);
    std::printf("[%2d] %s %016llx%016llx%016llx%016llx\n", slot++, phase,
        (unsigned long long)c.l[3], (unsigned long long)c.l[2],
        (unsigned long long)c.l[1], (unsigned long long)c.l[0]);
}
int main() {
    mfold::SparseMat A, B, C;
    fcirc::build_matrices(A, B, C);
    auto ld = [](const std::array<std::uint64_t,4>& c) {
        fp::fe x{}; std::memcpy(x.l.data(), c.data(), 32);
        fp::fe rr{}; std::memcpy(rr.l.data(), pallas_gen::RR.data(), 32);
        return fp::fe_mul(x, rr); };
    auto wit = [&](const std::array<std::uint64_t,4>& dp, const std::array<std::uint64_t,4>& dn,
                   const std::array<std::uint64_t,4>& pt) {
        std::vector<fp::fe> z(fcirc::NZ, fp::fe_zero());
        z[fcirc::Z_DPREV] = ld(dp); z[fcirc::Z_DNEW] = ld(dn);
        z[fcirc::Z_PTHASH] = ld(pt); z[fcirc::Z_COMPUTED] = ld(pt);
        z[fcirc::Z_NONCES] = fp::fe_from_u64(7); z[fcirc::Z_NONCEPT] = fp::fe_from_u64(8);
        z[fcirc::Z_LT] = fp::fe_one(); z[fcirc::Z_SELF] = fp::fe_zero();
        z[fcirc::Z_ISPAD] = fp::fe_zero(); z[fcirc::Z_PC] = fp::fe_from_u64(1);
        z[fcirc::Z_SELEXEC] = fp::fe_one(); z[fcirc::Z_NOTPAD] = fp::fe_one();
        z[fcirc::Z_H] = fp::fe_from_u64(1); z[fcirc::Z_ONE] = fp::fe_one();
        return z; };
    mfold::Relaxed U = mfold::fresh(wit(golden::FX_D0, golden::FX_D1, golden::FX_D0), fcirc::NROWS);
    mfold::Relaxed J = mfold::fresh(wit(golden::FX_D1, golden::FX_D2, golden::FX_D1), fcirc::NROWS);
    // mirror multifold's absorb sequence EXACTLY (mfold.hpp lines, annotated)
    for (const auto& v : U.z)  show("U.z", v);
    for (const auto& e : U.E)  show("U.E", e);
    for (const auto& v : J.z)  show("J.z", v);
    for (const auto& e : J.E)  show("J.E", e);
    mfold::MultifoldResult M1 = mfold::multifold(A,B,C,U,{J});
    for (const auto& t : M1.T[0]) show("T0", t);
    fp::fe s = fp::fe_to_canonical(M1.seed);
    std::printf("cpp_seed %016llx%016llx%016llx%016llx\n",
        (unsigned long long)s.l[3], (unsigned long long)s.l[2],
        (unsigned long long)s.l[1], (unsigned long long)s.l[0]);
    return 0;
}

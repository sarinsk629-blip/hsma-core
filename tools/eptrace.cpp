#include <hsma/fexec_circuit.hpp>
#include "epoch_golden.hpp"
#include "mfold_golden.hpp"
#include <cstdio>
#include <cstring>
using namespace hsma;
static int slot = 0;
static void show(const char* ph, const fp::fe& x) {
    fp::fe c = fp::fe_to_canonical(x);
    std::printf("[%2d] %s %016llx%016llx%016llx%016llx\n", slot++, ph,
        (unsigned long long)c.l[3], (unsigned long long)c.l[2],
        (unsigned long long)c.l[1], (unsigned long long)c.l[0]);
}
int main() {
    mfold::SparseMat A, B, C;
    fcirc::build_matrices(A, B, C);
    auto ld = [](const std::array<std::uint64_t,4>& c) {
        fp::fe x{}; std::memcpy(x.l.data(), c.data(), 32); return x; };
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
    mfold::Relaxed H = mfold::fresh(wit(golden::EP_PREV, golden::EP_DHEAD, golden::EP_PT, 0, false, 0, 1), fcirc::NROWS);
    mfold::Relaxed X = mfold::fresh(wit(golden::EP_DHEAD, golden::EP_DEXEC, golden::EP_PT, 1, false, 7, 8), fcirc::NROWS);
    // THE TRACE: mfold::multifold's absorb sequence, slot by slot
    show("U.u", H.u);
    for (const auto& v : H.z) show("H.z", v);
    for (const auto& e : H.E) show("H.E", e);
    show("J.u", X.u);
    for (const auto& v : X.z) show("X.z", v);
    for (const auto& e : X.E) show("X.E", e);
    mfold::MultifoldResult M1 = mfold::multifold(A,B,C,H,{X});
    for (const auto& t : M1.T[0]) show("T0", t);
    fp::fe s = fp::fe_to_canonical(M1.seed);
    std::printf("cpp_seed %016llx%016llx%016llx%016llx\n",
        (unsigned long long)s.l[3], (unsigned long long)s.l[2],
        (unsigned long long)s.l[1], (unsigned long long)s.l[0]);
    // the golden's key slots for the diff
    std::printf("gold r1 = %016llx%016llx%016llx%016llx\n",
        (unsigned long long)golden::EP_R1[0][3], (unsigned long long)golden::EP_R1[0][2],
        (unsigned long long)golden::EP_R1[0][1], (unsigned long long)golden::EP_R1[0][0]);
    return 0;
}

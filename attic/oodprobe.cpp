#include <hsma/whir.hpp>
#include "whir_golden.hpp"
#include <cstdio>
using namespace hsma;
int main() {
    std::vector<fp::fe> evals;
    for (unsigned i = 0; i < (1u << golden::WHIR_NV); ++i) {
        char lab[48]; std::snprintf(lab, sizeof(lab), "hsma-whir-golden-v1|f|%u", i);
        std::uint8_t dg[32]; digest::sha256((const std::uint8_t*)lab, std::strlen(lab), dg);
        std::array<std::uint64_t,4> l{};
        for (int b = 0; b < 4; ++b) for (int by = 0; by < 8; ++by)
            l[b] |= (std::uint64_t)dg[8*b + by] << (8*by);
        while (whir::can_geq_p(l)) l = whir::can_sub_p(l);
        evals.push_back(fp::fe_from_canonical_limbs(l));
    }
    std::vector<fp::fe> tau0;   // golden row 0, canonical -> Montgomery
    for (unsigned w = 0; w < golden::WHIR_NV; ++w)
        tau0.push_back(fp::fe_from_canonical_limbs(std::array<std::uint64_t,4>{
            golden::WHIR_TAU[w][0], golden::WHIR_TAU[w][1],
            golden::WHIR_TAU[w][2], golden::WHIR_TAU[w][3]}));
    fp::fe o = whir::ood_eval(evals, tau0);
    fp::fe c = fp::fe_to_canonical(o);
    std::printf("cpp_ood0(golden-tau) %016llx%016llx%016llx%016llx\n",
        (unsigned long long)c.l[3], (unsigned long long)c.l[2],
        (unsigned long long)c.l[1], (unsigned long long)c.l[0]);
    std::printf("golden_ood0          %016llx%016llx%016llx%016llx\n",
        (unsigned long long)golden::WHIR_OOD[0][3], (unsigned long long)golden::WHIR_OOD[0][2],
        (unsigned long long)golden::WHIR_OOD[0][1], (unsigned long long)golden::WHIR_OOD[0][0]);
    return 0;
}

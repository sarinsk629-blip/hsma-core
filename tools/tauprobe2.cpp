#include <hsma/whir.hpp>
#include "whir_golden.hpp"
#include <cstdio>
using namespace hsma;
int main() {
    std::byte cb[32];
    for (int k = 0; k < 4; ++k)
        for (int by = 0; by < 8; ++by)
            cb[8*k + by] = std::byte((unsigned char)(golden::WHIR_C[k] >> (8*by)));
    char lab[48]; std::snprintf(lab, sizeof(lab), "HSMA_WHIR_TAU|%u|%u", 0u, 0u);
    std::uint8_t dg[32]; whir::sha_cat(lab, cb, dg);
    fp::fe t = whir::digest_scalar(dg);
    fp::fe c = fp::fe_to_canonical(t);
    std::printf("cpp_tau000: %016llx%016llx%016llx%016llx\n",
        (unsigned long long)c.l[3], (unsigned long long)c.l[2],
        (unsigned long long)c.l[1], (unsigned long long)c.l[0]);
    std::printf("golden    : %016llx%016llx%016llx%016llx\n",
        (unsigned long long)golden::WHIR_TAU[0][3], (unsigned long long)golden::WHIR_TAU[0][2],
        (unsigned long long)golden::WHIR_TAU[0][1], (unsigned long long)golden::WHIR_TAU[0][0]);
    return 0;
}

#include <hsma/whir.hpp>
#include <cstdio>
#include <cstring>
using namespace hsma;
int main() {
    std::vector<fp::fe> evals;
    for (unsigned i = 0; i < 1024; ++i) {
        char lab[48]; std::snprintf(lab, sizeof(lab), "hsma-whir-golden-v1|f|%u", i);
        std::uint8_t dg[32]; digest::sha256((const std::uint8_t*)lab, std::strlen(lab), dg);
        std::array<std::uint64_t,4> l{};
        for (int b = 0; b < 4; ++b) for (int by = 0; by < 8; ++by)
            l[b] |= (std::uint64_t)dg[8*b + by] << (8*by);
        while (whir::can_geq_p(l)) l = whir::can_sub_p(l);
        evals.push_back(fp::fe_from_canonical_limbs(l));
    }
    fp::fe C = pcs::commit(evals);
    std::byte cb[32]; fp::fe_to_le_bytes(fp::fe_to_canonical(C), cb);
    std::printf("cb: ");
    for (int i = 0; i < 32; ++i) std::printf("%02x", std::to_integer<unsigned>(cb[i]));
    std::printf("\n");
    char lab[48]; std::snprintf(lab, sizeof(lab), "HSMA_WHIR_TAU|%u|%u", 0u, 0u);
    std::printf("lab: ");
    for (std::size_t i = 0; i < std::strlen(lab); ++i) std::printf("%02x", (unsigned)lab[i]);
    std::printf("  [%s]\n", lab);
    std::uint8_t dg[32]; whir::sha_cat(lab, cb, dg);
    std::printf("dg: ");
    for (int i = 0; i < 32; ++i) std::printf("%02x", dg[i]);
    std::printf("\n");
    fp::fe t = whir::digest_scalar(dg);
    fp::fe c = fp::fe_to_canonical(t);
    std::printf("tau000: %016llx%016llx%016llx%016llx\n",
        (unsigned long long)c.l[3], (unsigned long long)c.l[2],
        (unsigned long long)c.l[1], (unsigned long long)c.l[0]);
    return 0;
}

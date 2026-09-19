#include <hsma/whir.hpp>
#include <cstdio>
#include <array>
using namespace hsma;
static void put(const char* tag, const fp::fe& x) {
    fp::fe c = fp::fe_to_canonical(x);
    std::printf("%s %016llx%016llx%016llx%016llx\n", tag,
        (unsigned long long)c.l[3], (unsigned long long)c.l[2],
        (unsigned long long)c.l[1], (unsigned long long)c.l[0]);
}
int main() {
    char lab[48]; std::snprintf(lab, sizeof(lab), "hsma-whir-golden-v1|f|%u", 0u);
    std::uint8_t dg[32]; digest::sha256((const std::uint8_t*)lab, std::strlen(lab), dg);
    std::array<std::uint64_t,4> l{};
    for (int b = 0; b < 4; ++b) for (int by = 0; by < 8; ++by)
        l[b] |= (std::uint64_t)dg[8*b + by] << (8*by);
    while (whir::can_geq_p(l)) l = whir::can_sub_p(l);
    put("evals0", fp::fe_from_canonical_limbs(l));
    fp::Sponge sp(dom::Dom::HSM_SUMCHECK_v1);
    sp.absorb(fp::fe_from_u64(1));
    sp.absorb(fp::fe_from_u64(2));
    put("sponge12", sp.squeeze());
    std::vector<fp::fe> evals;
    for (unsigned i = 0; i < 1024; ++i) {
        std::snprintf(lab, sizeof(lab), "hsma-whir-golden-v1|f|%u", i);
        digest::sha256((const std::uint8_t*)lab, std::strlen(lab), dg);
        for (int b = 0; b < 4; ++b) l[b] = 0;
        for (int b = 0; b < 4; ++b) for (int by = 0; by < 8; ++by)
            l[b] |= (std::uint64_t)dg[8*b + by] << (8*by);
        while (whir::can_geq_p(l)) l = whir::can_sub_p(l);
        evals.push_back(fp::fe_from_canonical_limbs(l));
    }
    put("fullC", pcs::commit(evals));
    return 0;
}

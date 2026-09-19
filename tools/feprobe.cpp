#include <hsma/fexec_circuit.hpp>   // pulls fe (Pallas) via mfold
#include <hsma/fev.hpp>             // fev (Vesta)
#include <cstdio>
using namespace hsma;
static void pp(const char* tag, const fp::fe& x) {
    fp::fe c = fp::fe_to_canonical(x);
    std::printf("%s %016llx%016llx%016llx%016llx\n", tag,
        (unsigned long long)c.l[3], (unsigned long long)c.l[2],
        (unsigned long long)c.l[1], (unsigned long long)c.l[0]);
}
static void pv(const char* tag, const fq::fev& x) {
    fq::fev c = fq::fev_to_canonical(x);
    std::printf("%s %016llx%016llx%016llx%016llx\n", tag,
        (unsigned long long)c.l[3], (unsigned long long)c.l[2],
        (unsigned long long)c.l[1], (unsigned long long)c.l[0]);
}
int main() {
    // Pallas: from_u64 semantics
    pp("P from_u64(2)      ", fp::fe_from_u64(2));
    pp("P fe_one()         ", fp::fe_one());
    // Pallas: mul semantics (2*3 = 6 raw? 6/R? 6R?)
    pp("P 2*3              ", fp::fe_mul(fp::fe_from_u64(2), fp::fe_from_u64(3)));
    // Pallas: to_canonical on a raw value (identity or /R?)
    pp("P to_canon(raw 2)  ", fp::fe_to_canonical(fp::fe_from_u64(2)));
    // Vesta: the same battery
    pv("V from_u64(2)      ", fq::fev_from_u64(2));
    pv("V 2*3              ", fq::fev_mul(fq::fev_from_u64(2), fq::fev_from_u64(3)));
    pv("V to_canon(raw 2)  ", fq::fev_to_canonical(fq::fev_from_u64(2)));
    return 0;
}

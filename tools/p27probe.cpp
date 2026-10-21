// P1-07 calibration probe: prints poseidon3v(0, l, r) canonical limbs.
#include <hsma/poseidon_v.hpp>
#include <hsma/fev.hpp>
#include <cstdio>
using namespace hsma;
static void put(const fq::fev& v, const char* tag) {
    fq::fev c = fq::fev_to_canonical(v);
    std::printf("%s %016llx %016llx %016llx %016llx\n", tag,
        (unsigned long long)c.l[0], (unsigned long long)c.l[1],
        (unsigned long long)c.l[2], (unsigned long long)c.l[3]);
}
int main() {
    put(vp3::poseidon3v(0, fq::fev_from_u64(1), fq::fev_from_u64(2)), "P01");
    put(vp3::poseidon3v(0, fq::fev_from_u64(0xdeadbeefcafebabeULL),
                           fq::fev_from_u64(0x1234567890abcdefULL)), "P02");
    put(vp3::poseidon3v(0, fq::fev_sub(fq::fev_zero(), fq::fev_one()),
                           fq::fev_from_u64(5)), "P03");
    return 0;
}

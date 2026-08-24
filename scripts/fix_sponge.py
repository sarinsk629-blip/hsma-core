with open("include/hsma/poseidon.hpp", "r") as f:
    c = f.read()

bad_squeeze = """    fe squeeze() noexcept {
        absorb(fe_from_u64(count_));
        absorb(fe_one());
        if (idx_ != 0) p3_permute(st_);
        p3_permute(st_);
        idx_ = 0; count_ = 0;
        return st_.s0;
    }"""

good_squeeze = """    fe squeeze() noexcept {
        absorb(fe_from_u64(count_));
        absorb(fe_one());
        if (idx_ != 0) {
            p3_permute(st_);
            idx_ = 0;
        }
        count_ = 0;
        return st_.s0;
    }"""

c = c.replace(bad_squeeze, good_squeeze)
with open("include/hsma/poseidon.hpp", "w") as f:
    f.write(c)

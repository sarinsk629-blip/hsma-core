with open("scripts/gen_constants.py", "r") as f:
    c = f.read()

# Fix 1: Make Python generate true Montgomery golden products (a * b * R^-1 mod p)
c = c.replace('l4((a*b)%p)', 'l4((a * b * pow(1<<256, -1, p)) % p)')

with open("scripts/gen_constants.py", "w") as f:
    f.write(c)

with open("conformance/test_step2.cpp", "r") as f:
    c2 = f.read()

# Fix 2: Hit the accumulator with maximum bounds to properly test the 126-bit clamp
c2 = c2.replace('for (int i = 0; i < 1000; ++i) acc.accumulate(INT64_MAX / 2, INT32_MAX, sc);',
                'acc.accumulate(numcore::ScratchAcc::HI_BOUND, sc); acc.accumulate(numcore::ScratchAcc::HI_BOUND, sc);')
c2 = c2.replace('for (int i = 0; i < 1000; ++i) acc.accumulate(-INT64_MAX / 2, INT32_MAX, sc);',
                'acc.accumulate(numcore::ScratchAcc::LO_BOUND, sc); acc.accumulate(numcore::ScratchAcc::LO_BOUND, sc);')

with open("conformance/test_step2.cpp", "w") as f:
    f.write(c2)

import sys, re
sys.path.insert(0, "scripts")
# reuse step32's machinery by importing its body up to the identity
src = open("scripts/gen/steps/step32.py").read()
# exec everything except the final assert/emission: hack - exec with a flag
src = src.replace('assert Wre == Wfo, "THE COMMITMENT FOLD IDENTITY FAILED"', '')
src = src.replace('P("[step32] commitment fold IDENTITY SELF-CHECKED (recommit == fold, exact in the order-p group)")', '')
src = src.replace('assert onv(Wre) and onv(CT_1)', '')
src = src.replace('assert Wbad != Wfo', '')
exec(compile(src, "step32_noid", "exec"))
# now: the identity pieces are in scope
print("rho_p        =", hex(rho_p))
print("zU[0]        =", hex(zU[0]), "| zJ[0] =", hex(zJ[0]), "| F1z[0] =", hex(F1[1][0]))
expect0 = (zU[0] + r1v[0]*zJ[0]) % p_
print("zU0 + r*zJ0  =", hex(expect0), "| match F1z0:", expect0 == F1[1][0])
for i in range(8):
    e = (zU[i] + r1v[0]*zJ[i]) % p_
    if e != F1[1][i]:
        print("Z-MISMATCH at coord", i, ":", hex(e), "vs", hex(F1[1][i])); break
else:
    print("z-fold: ALL COORDS MATCH")
# bases sanity: h_0 scalar vs its point - recompute H_0 = [h_0]G and compare to the golden row
H0 = ec_mul(bases[0][0], Gv)
print("H0 recomputed:", hex(H0[0]), hex(H0[1]))
print("H0 golden    :", hex(bases[0][1][0]), hex(bases[0][1][1]))
print("bases self-consistent:", H0 == bases[0][1])

# HSMA :: gen/steps/step31.py - P1-11 (GAP-06 core, DEC-229).
# The HyperNova multifold golden: the 4-row circuit from the probe, strict
# sequential witnesses, fold1 (fresh+fresh -> relaxed, E!=0), fold2 (relaxed+
# fresh -> relaxed), FS challenges (Sponge seed + P3(seed,j)), all vectors
# bit-exact vs C++. Python mirrors mfold.hpp verbatim (CA-R126 self-checks
# pre-emit; CA-R127 honored - flat arrays only; CA-R133: bit-order N/A here).
import os, sys, re
_HERE = os.path.dirname(os.path.abspath(__file__))
_sp = os.path.abspath(os.path.join(_HERE, ".."))
if _sp not in sys.path: sys.path.insert(0, _sp)
import gen_common as GC
import hashlib

M64 = (1 << 64) - 1

def _step31():
    P = lambda *a: print(*a, flush=True)
    # p from pallas_params_gen.hpp
    pt = open("build/generated/pallas_params_gen.hpp").read()
    hx = lambda w: int(re.search(r'0x([0-9a-fA-F]+)', w).group(1), 16)
    pm = re.search(r'MOD\s*\{\s*\{\s*(.*?)\}\s*\}', pt, re.S)
    assert pm, "pallas MOD not found"
    l = [hx(w) for w in pm.group(1).split(",")]
    p_ = l[0] | l[1] << 64 | l[2] << 128 | l[3] << 192
    # sponge_ref extracted (the proven pattern)
    src = open("scripts/gen_constants.py").read()
    i0 = src.index("def sponge_ref"); i2 = src.index("def emit_poseidon")
    region = src[i0:i2]; compile(region, "sponge_region", "exec")
    import ast as _ast
    mt = _ast.parse(src); consts = {}
    def _try(t, node):
        try: consts[t.id] = _ast.literal_eval(node.value)
        except Exception: pass
    for node in mt.body:
        if isinstance(node, _ast.Assign):
            for t in node.targets:
                if isinstance(t, _ast.Name): _try(t, node)
                elif isinstance(t, _ast.Tuple) and isinstance(node.value, _ast.Tuple):
                    for e, vv in zip(t.elts, node.value.elts):
                        if isinstance(e, _ast.Name): _try(e, vv and node)
    # fix: tuple values pair positionally
    consts = {}
    for node in mt.body:
        if isinstance(node, _ast.Assign):
            for t in node.targets:
                if isinstance(t, _ast.Name):
                    try: consts[t.id] = _ast.literal_eval(node.value)
                    except Exception: pass
                elif isinstance(t, _ast.Tuple) and isinstance(node.value, _ast.Tuple):
                    for e, vv in zip(t.elts, node.value.elts):
                        if isinstance(e, _ast.Name):
                            try: consts[e.id] = _ast.literal_eval(vv)
                            except Exception: pass
    ns = {k: consts[k] for k in ("POSEIDON_ALPHA","POSEIDON_RF","POSEIDON_RP","POSEIDON_T")}
    exec(compile(region, "sponge_region", "exec"), ns)
    sponge = ns["sponge_ref"]
    # MDS/RC positional + SUMCHECK IV by the iv_of contract
    qt = open("build/generated/poseidon_params_gen.hpp").read()
    allrows = [[hx(w) for w in m.group(1).split(",")] for m in
               re.finditer(r'\{\s*(0x[0-9a-fA-F]{16}[uU][lL][lL](?:\s*,\s*0x[0-9a-fA-F]{16}[uU][lL][lL]){3})\s*\}', qt)]
    assert len(allrows) >= 89
    cv = lambda r4: r4[0] | r4[1] << 64 | r4[2] << 128 | r4[3] << 192
    MDS = [[cv(allrows[3*r_+c_]) for c_ in range(3)] for r_ in range(3)]
    RC = [cv(r) for r in allrows[9:89]]
    nonce = 0
    while True:
        dg = hashlib.sha256(b"HSM_IV_v1|HSM_SUMCHECK_v1" + nonce.to_bytes(8,"little")).digest()
        cand = int.from_bytes(dg, "little")
        if cand < p_: IV = cand; break
        nonce += 1
    fadd = lambda a,b:(a+b)%p_; fsub=lambda a,b:(a-b)%p_; fmul=lambda a,b:a*b%p_
    def poseidon3(lv, rv): return perm3([lv%p_, rv%p_, IV], MDS, RC, p_)[0]   # s0, not the state
    def perm3(s, MDS, RC, p_):
        rc = 0
        def mix(): return [sum(MDS[r_][c_]*s[c_] for c_ in range(3)) % p_ for r_ in range(3)]
        for _ in range(4):
            for _t in range(3): s[_t] = (s[_t] + RC[rc]) % p_; rc += 1
            s[:] = [pow(v,5,p_) for v in s]; s[:] = mix()
        for _ in range(56):
            s[0] = (s[0] + RC[rc]) % p_; rc += 1
            s[0] = pow(s[0],5,p_); s[:] = mix()
        for _ in range(4):
            for _t in range(3): s[_t] = (s[_t] + RC[rc]) % p_; rc += 1
            s[:] = [pow(v,5,p_) for v in s]; s[:] = mix()
        assert rc == 80
        return s
    # hashlib import (top of file pattern)

    # ---- the circuit (mfold.hpp probe verbatim) ----
    ROWS, COLS, K = 4, 8, 2
    A = [(0,0,1),(0,1,1),(1,2,1),(2,4,1),(3,5,1)]
    B = [(0,2,1),(1,3,1),(2,4,1),(3,5,1)]
    C = [(0,3,1),(1,7,1),(2,5,1),(3,6,1)]
    def mat_vec(M, z):
        out = [0]*ROWS
        for r_, c_, v in M: out[r_] = fadd(out[r_], fmul(v, z[c_]))
        return out
    def wit(a,b,c,d):
        z = [0]*8
        z[0]=a; z[1]=b; z[2]=c; z[4]=d
        z[3] = fmul(fadd(z[0],z[1]), z[2])
        z[7] = fmul(z[2], z[3])
        z[5] = fmul(z[4], z[4])
        z[6] = fmul(z[5], z[5])
        return z
    def sat(u, z, E):
        az, bz, cz = mat_vec(A,z), mat_vec(B,z), mat_vec(C,z)
        for i in range(ROWS):
            if fmul(az[i],bz[i]) != fadd(fmul(u,cz[i]), E[i]): return False
        return True
    def cross(U_, J_):
        azU,bzU,czU = mat_vec(A,U_[1]),mat_vec(B,U_[1]),mat_vec(C,U_[1])
        azJ,bzJ,czJ = mat_vec(A,J_[1]),mat_vec(B,J_[1]),mat_vec(C,J_[1])
        return [fsub(fsub(fadd(fmul(azU[i],bzJ[i]), fmul(azJ[i],bzU[i])),
                          fmul(U_[0],czJ[i])), fmul(J_[0],czU[i])) for i in range(ROWS)]
    def multifold(U_, js):
        Ts = [cross(U_, j) for j in js]
        seed = sponge(p_, IV, [U_[0]] + U_[1] + U_[2] +
                      [x for j in js for x in ([j[0]] + j[1] + j[2] + Ts[js.index(j)])], MDS, RC)
        rs = [poseidon3(seed, j) for j in range(len(js))]
        u2 = fadd(U_[0], sum(rs) % p_)
        z2 = [fadd(U_[1][t], sum(fmul(rs[j], js[j][1][t]) for j in range(len(js))) % p_) for t in range(COLS)]
        E2 = [fadd(U_[2][i], sum(fmul(rs[j], Ts[j][i]) for j in range(len(js))) % p_) for i in range(ROWS)]
        return (u2, z2, E2), Ts, rs, seed
    def fresh(z): return (1, z, [0]*ROWS)

    zU, zJ = wit(3,4,5,6), wit(2,1,3,4)
    U_, J_ = fresh(zU), fresh(zJ)
    assert sat(*U_) and sat(*J_), "emitter witnesses unsat"
    # fold1: fresh+fresh -> relaxed
    F1, T1v, r1v, seed1 = multifold(U_, [J_])
    assert sat(*F1), "fold1 unsat"
    assert F1[0] == fadd(1, r1v[0]) and any(e != 0 for e in F1[2]), "fold1 relaxed-state wrong"
    # fold2: relaxed + fresh -> relaxed (the HyperNova loop)
    F2, T2v, r2v, seed2 = multifold(F1, [J_])
    assert sat(*F2), "fold2 unsat"
    # negative: tampered instance corrupts the accumulator
    Bad = (1, [x % p_ for x in zJ], [0]*ROWS); Bad[1][0] = fadd(Bad[1][0], 1)
    FB, _, _, _ = multifold(U_, [Bad])
    assert not sat(*FB), "tamper negative did not corrupt"
    P("[step31] multifold SELF-CHECKED: fold1 SAT (E!=0), fold2 SAT, tamper corrupts")

    # emission - FLAT arrays (CA-R127), canonical limbs
    row = lambda v: GC.row4(int(v) % p_)
    def arr(name, vals):
        return ("inline constexpr std::array<std::array<std::uint64_t, 4>, %d> %s {{\n" % (len(vals), name)
                + "".join("  { " + row(v) + " },\n" for v in vals) + "}};\n")
    def one(name, v): return "inline constexpr std::array<std::uint64_t, 4> %s { " % name + row(v) + " };\n"
    parts = ["// HSMA :: mfold_golden.hpp - P1-11 golden (DEC-229). CANONICAL limbs.",
             "#pragma once", "#include <array>", "#include <cstdint>",
             "namespace hsma::golden {",
             "inline constexpr unsigned MF_ROWS = %du, MF_COLS = %du, MF_K = %du;" % (ROWS, COLS, K),
             one("MF_SEED1", seed1), one("MF_R1", r1v[0]),
             arr("MF_T1", T1v[0]),
             arr("MF_F1_Z", F1[1]), one("MF_F1_U", F1[0]), arr("MF_F1_E", F1[2]),
             one("MF_SEED2", seed2), arr("MF_R2", r2v),
             arr("MF_T2", T2v[0]),
             arr("MF_F2_Z", F2[1]), one("MF_F2_U", F2[0]), arr("MF_F2_E", F2[2]),
             "} // namespace hsma::golden"]
    GC.emit_hpp("mfold_golden.hpp", "\n".join(parts) + "\n")
    P("[step31][emit] mfold_golden.hpp (fold1+fold2: seeds, challenges, T, z/u/E)")

_step31()

# HSMA :: gen/steps/step33.py - P1-13a (GAP-07, DEC-231).
# The f_exec circuit golden: the whitepaper's five constraints as sparse rows
# (fcirc::build_matrices verbatim), witnesses from the NATIVE digest chain
# (perm3 @ HSM_FOLD_v1 - the proven Python perm), the multifold over 2 EXEC
# steps, PAD-neutrality, PC receipts, and the negatives. CANONICAL Python
# arithmetic throughout (CA-R142: the table law - domain-agnostic by design).
import os, sys, re, hashlib
_HERE = os.path.dirname(os.path.abspath(__file__))
_sp = os.path.abspath(os.path.join(_HERE, ".."))
if _sp not in sys.path: sys.path.insert(0, _sp)
import gen_common as GC

def _step33():
    P = lambda *a: print(*a, flush=True)
    hx = lambda w: int(re.search(r'0x([0-9a-fA-F]+)', w).group(1), 16)
    pt = open("generated/pallas_params_gen.hpp").read()
    pm = re.search(r'MOD\s*\{\s*\{\s*(.*?)\}\s*\}', pt, re.S)
    l = [hx(w) for w in pm.group(1).split(",")]
    p_ = l[0] | l[1] << 64 | l[2] << 128 | l[3] << 192
    src = open("scripts/gen_constants.py").read()
    region = src[src.index("def sponge_ref"):src.index("def emit_poseidon")]
    compile(region, "sponge_region", "exec")
    import ast as _ast
    consts = {}
    for node in _ast.parse(src).body:
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
    qt = open("generated/poseidon_params_gen.hpp").read()
    allrows = [[hx(w) for w in m.group(1).split(",")] for m in
               re.finditer(r'\{\s*(0x[0-9a-fA-F]{16}[uU][lL][lL](?:\s*,\s*0x[0-9a-fA-F]{16}[uU][lL][lL]){3})\s*\}', qt)]
    cv = lambda r4: r4[0] | r4[1] << 64 | r4[2] << 128 | r4[3] << 192
    MDS = [[cv(allrows[3*r_+c_]) for c_ in range(3)] for r_ in range(3)]
    RC = [cv(r) for r in allrows[9:89]]
    def derive_iv(tag):
        nonce = 0
        while True:
            dg = hashlib.sha256(b"HSM_IV_v1|" + tag.encode() + nonce.to_bytes(8,"little")).digest()
            cand = int.from_bytes(dg, "little")
            if cand < p_: return cand
            nonce += 1
    IV_FOLD = derive_iv("HSM_FOLD_v1"); IV_SC = derive_iv("HSM_SUMCHECK_v1")
    def perm3(s):
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
        return s[0]
    p3fold = lambda lv, rv: perm3([lv % p_, rv % p_, IV_FOLD])
    fadd = lambda a,b:(a+b)%p_; fsub=lambda a,b:(a-b)%p_; fmul=lambda a,b:a*b%p_

    # ---- the circuit rows (fcirc::build_matrices verbatim) ----
    NZ, NROWS = 16, 8
    (Z_U,Z_DPREV,Z_DNEW,Z_PTHASH,Z_COMPUTED,Z_NONCES,Z_NONCEPT,
     Z_LT,Z_SELF,Z_ISPAD,Z_PC,Z_SELEXEC,Z_BALNEW,Z_H,Z_NOTPAD,Z_ONE) = range(16)
    A = [(0,Z_NOTPAD,1)]; B = [(0,Z_COMPUTED,1),(0,Z_PTHASH,-1)]; C = []
    A += [(1,Z_NOTPAD,1)]; B += [(1,Z_NONCES,1),(1,Z_NONCEPT,-1),(1,Z_ONE,1)]
    A += [(2,Z_LT,1)]; B += [(2,Z_LT,1)]; C += [(2,Z_LT,1)]
    A += [(3,Z_ISPAD,1)]; B += [(3,Z_ISPAD,1)]; C += [(3,Z_ISPAD,1)]
    A += [(4,Z_SELF,1)]; B += [(4,Z_SELF,1)]; C += [(4,Z_SELF,1)]
    A += [(5,Z_PC,1)]; B += [(5,Z_PC,1)]; C += [(5,Z_H,1)]          # H = PC^2
    A += [(6,Z_H,1)]; B += [(6,Z_PC,1)]; C += [(6,Z_H,3),(6,Z_PC,-2)]  # H*PC = 3H-2PC
    A += [(7,Z_ISPAD,1)]; B += [(7,Z_DNEW,1),(7,Z_DPREV,-1)]
    def mat_vec(M, z):
        out = [0]*NROWS
        for r_, c_, v in M: out[r_] = fadd(out[r_], fmul(v, z[c_]))
        return out
    def sat(u, z, E):
        az, bz, cz = mat_vec(A,z), mat_vec(B,z), mat_vec(C,z)
        return all(fmul(az[i],bz[i]) == fadd(fmul(u,cz[i]), E[i]) for i in range(NROWS))
    def cross(U_, J_):
        azU,bzU,czU = mat_vec(A,U_[1]),mat_vec(B,U_[1]),mat_vec(C,U_[1])
        azJ,bzJ,czJ = mat_vec(A,J_[1]),mat_vec(B,J_[1]),mat_vec(C,J_[1])
        return [fsub(fsub(fadd(fmul(azU[i],bzJ[i]), fmul(azJ[i],bzU[i])),
                          fmul(U_[0],czJ[i])), fmul(J_[0],czU[i])) for i in range(NROWS)]
    def multifold(U_, js):
        Ts = [cross(U_, j) for j in js]
        seed = sponge(p_, IV_SC, [U_[0]] + U_[1] + U_[2] +
                      [x for j in js for x in ([j[0]] + j[1] + j[2] + Ts[js.index(j)])], MDS, RC)
        rs = [perm3([seed % p_, j, IV_SC]) for j in range(len(js))]
        u2 = fadd(U_[0], sum(rs) % p_)
        z2 = [fadd(U_[1][t], sum(fmul(rs[j], js[j][1][t]) for j in range(len(js))) % p_) for t in range(NZ)]
        E2 = [fadd(U_[2][i], sum(fmul(rs[j], Ts[j][i]) for j in range(len(js))) % p_) for i in range(NROWS)]
        return (u2, z2, E2), Ts, rs, seed

    # ---- native semantics: the digest chain (fold.hpp's f_exec absorb) ----
    # two EXEC decrees; pt_hash_i = the packed hash (DRBG here; the golden pins)
    seedm = b"hsma-fexec-golden-v1"
    pth = [int.from_bytes(hashlib.sha256(seedm + b"|pt|%d" % i).digest(), "little") % p_ for i in range(2)]
    d0 = int.from_bytes(hashlib.sha256(seedm + b"|d0").digest(), "little") % p_
    d1 = p3fold(d0, pth[0])          # exec 1 absorbs
    d2 = p3fold(d1, pth[1])          # exec 2 absorbs
    def step_z(dprev, dnew, pth_i, pc, sel):
        z = [0]*NZ
        z[Z_DPREV], z[Z_DNEW], z[Z_PTHASH], z[Z_COMPUTED] = dprev, dnew, pth_i, pth_i
        z[Z_NONCES], z[Z_NONCEPT] = 7, 8          # nonce_s + 1 = nonce_pt
        z[Z_LT], z[Z_SELF], z[Z_ISPAD] = 1, 0, 0
        z[Z_PC], z[Z_SELEXEC], z[Z_NOTPAD] = pc, sel, 1 - z[Z_ISPAD]
        z[Z_ONE] = 1   # CA-R144: the ONE wire
        z[Z_H] = (pc*pc) % p_
        return z
    z1 = step_z(d0, d1, pth[0], 1, 1)
    z2 = step_z(d1, d2, pth[1], 1, 1)
    U_, J_ = (1, z1, [0]*NROWS), (1, z2, [0]*NROWS)
    assert sat(*U_), "step1 witness unsat"
    assert sat(*J_), "step2 witness unsat"
    F1, T1v, r1v, seed1 = multifold(U_, [J_])
    assert sat(*F1), "fold unsat"
    # PAD-neutrality live: a PAD step folds neutral (dnew == dprev)
    zp = step_z(F1[1][Z_DPREV], F1[1][Z_DPREV], 0, 1, 0); zp[Z_ISPAD] = 1; zp[Z_NOTPAD] = 0
    JP = (1, zp, [0]*NROWS); assert sat(*JP), "PAD witness unsat"
    F2, T2v, r2v, seed2 = multifold(F1, [JP])
    assert sat(*F2), "PAD fold unsat"
    # negatives (CA-R134): bad nonce -> R1 unsat; PC=3 -> cubic unsat
    zb = list(z1); zb[Z_NONCES] = 9
    assert not sat(1, zb, [0]*NROWS), "neg: bad nonce did not unsat"
    zpc = list(z1); zpc[Z_PC] = 3; zpc[Z_H] = 9
    assert not sat(1, zpc, [0]*NROWS), "neg: PC=3 did not unsat"
    P("[step33] fexec circuit SELF-CHECKED: 2 EXEC SAT, PAD-neutral fold SAT, nonce/PC negatives unsat")

    row = lambda v: GC.row4(int(v) % p_)
    def arr(name, vals):
        return ("inline constexpr std::array<std::array<std::uint64_t, 4>, %d> %s {{\n" % (len(vals), name)
                + "".join("  { " + row(v) + " },\n" for v in vals) + "}};\n")
    one = lambda name, v: "inline constexpr std::array<std::uint64_t, 4> %s { " % name + row(v) + " };\n"
    parts = ["// HSMA :: fexec_golden.hpp - P1-13a golden (DEC-231). CANONICAL limbs.",
             "#pragma once", "#include <array>", "#include <cstdint>",
             "namespace hsma::golden {",
             one("FX_D0", d0), one("FX_D1", d1), one("FX_D2", d2),
             one("FX_PT0", pth[0]), one("FX_PT1", pth[1]),
             one("FX_SEED1", seed1), one("MF_R1X", r1v[0]),
             arr("FX_T1", T1v[0]),
             arr("FX_F1_Z", F1[1]), one("FX_F1_U", F1[0]), arr("FX_F1_E", F1[2]),
             one("FX_SEED2", seed2),
             "} // namespace hsma::golden"]
    GC.emit_hpp("fexec_golden.hpp", "\n".join(parts) + "\n")
    P("[step33][emit] fexec_golden.hpp (digest chain, seeds, T, folded z/u/E)")

_step33()

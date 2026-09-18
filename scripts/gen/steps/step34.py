# HSMA :: gen/steps/step34.py - P1-13b (GAP-07 epoch loop + pi_E, DEC-232).
# The epoch: HEAD absorbs prev_digest -> EXEC x1 -> CLOSE; each step folds
# through the f_exec circuit matrices (PC transitions enforced); the final
# folded vectors go through the WHIR-wrap commitment structure -> pi_E.
# CANONICAL Python throughout (CA-R142); pre-emit self-checks (CA-R126);
# flat arrays (CA-R127); emitted contracts complete (CA-R145).
import os, sys, re, hashlib
_HERE = os.path.dirname(os.path.abspath(__file__))
_sp = os.path.abspath(os.path.join(_HERE, ".."))
if _sp not in sys.path: sys.path.insert(0, _sp)
import gen_common as GC

def _step34():
    P = lambda *a: print(*a, flush=True)
    hx = lambda w: int(re.search(r'0x([0-9a-fA-F]+)', w).group(1), 16)
    pt = open("build/generated/pallas_params_gen.hpp").read()
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
    qt = open("build/generated/poseidon_params_gen.hpp").read()
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

    # ---- the f_exec circuit rows (P1-13a verbatim) ----
    NZ, NROWS = 16, 8
    (Z_U,Z_DPREV,Z_DNEW,Z_PTHASH,Z_COMPUTED,Z_NONCES,Z_NONCEPT,
     Z_LT,Z_SELF,Z_ISPAD,Z_PC,Z_SELEXEC,Z_BALNEW,Z_H,Z_NOTPAD,Z_ONE) = range(16)
    A = [(0,Z_NOTPAD,1)]; B = [(0,Z_COMPUTED,1),(0,Z_PTHASH,-1)]; C = []
    A += [(1,Z_NOTPAD,1)]; B += [(1,Z_NONCES,1),(1,Z_NONCEPT,-1),(1,Z_ONE,1)]
    A += [(2,Z_LT,1)]; B += [(2,Z_LT,1)]; C += [(2,Z_LT,1)]
    A += [(3,Z_ISPAD,1)]; B += [(3,Z_ISPAD,1)]; C += [(3,Z_ISPAD,1)]
    A += [(4,Z_SELF,1)]; B += [(4,Z_SELF,1)]; C += [(4,Z_SELF,1)]
    A += [(5,Z_PC,1)]; B += [(5,Z_PC,1)]; C += [(5,Z_H,1)]
    A += [(6,Z_H,1)]; B += [(6,Z_PC,1)]; C += [(6,Z_H,3),(6,Z_PC,-2)]
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
        P("[probe] multifold: len(U_)=%d len(U_[1])=%d len(U_[2])=%d | len(js)=%d" % (len(U_), len(U_[1]), len(U_[2]), len(js)))
        for j in js: P("[probe]   len(j)=%d len(j[1])=%d len(j[2])=%d" % (len(j), len(j[1]), len(j[2])))
        Ts = [cross(U_, j) for j in js]
        P("[probe]   len(Ts[0])=%d" % len(Ts[0]))
        seed = sponge(p_, IV_SC, [U_[0]] + U_[1] + U_[2] +
                      [x for j in js for x in ([j[0]] + j[1] + j[2] + Ts[js.index(j)])], MDS, RC)
        rs = [perm3([seed % p_, j, IV_SC]) for j in range(len(js))]
        u2 = fadd(U_[0], sum(rs) % p_)
        z2 = []
        for t in range(NZ):
            try:
                acc = sum(fmul(rs[j], js[j][1][t]) for j in range(len(js))) % p_
            except IndexError:
                P("[crash] z2 t=%d | len(rs)=%d len(js)=%d len(js[0][1])=%d len(U_[1])=%d"
                  % (t, len(rs), len(js), len(js[0][1]), len(U_[1])))
                raise
            z2.append(fadd(U_[1][t], acc))
        E2 = []
        for i in range(NROWS):
            try:
                acc = sum(fmul(rs[j], Ts[j][i]) for j in range(len(js))) % p_
            except IndexError:
                P("[crash] E2 i=%d | len(Ts)=%d len(Ts[0])=%d len(U_[2])=%d"
                  % (i, len(Ts), len(Ts[0]), len(U_[2])))
                raise
            E2.append(fadd(U_[2][i], acc))
        return (u2, z2, E2), Ts, rs, seed
    def mkz(dprev, dnew, pth_i, pc, ispad, nonces=7, noncept=8):
        z = [0]*NZ
        z[Z_DPREV], z[Z_DNEW], z[Z_PTHASH], z[Z_COMPUTED] = dprev, dnew, pth_i, pth_i
        z[Z_NONCES], z[Z_NONCEPT] = nonces, noncept
        z[Z_LT], z[Z_SELF] = 1, 0
        z[Z_ISPAD], z[Z_NOTPAD] = ispad, 1 - ispad
        z[Z_PC] = pc; z[Z_H] = (pc*pc) % p_
        z[Z_SELEXEC] = 1 if pc == 1 and not ispad else 0
        z[Z_ONE] = 1
        return z

    # ---- THE EPOCH: prev_digest -> HEAD absorb -> EXEC -> CLOSE ----
    seedm = b"hsma-epoch-golden-v1"
    prev_digest = int.from_bytes(hashlib.sha256(seedm + b"|prev").digest(), "little") % p_
    pt_hash = int.from_bytes(hashlib.sha256(seedm + b"|pt0").digest(), "little") % p_
    # HEAD: absorbs prev_digest into the digest chain; nonce gate neutral
    # (the same circuit carries all PC values - selectors are the honest form)
    d_head = p3fold(prev_digest, pt_hash)
    z_head = mkz(prev_digest, d_head, pt_hash, 0, 0, nonces=0, noncept=1)  # 0+1=1: R1 satisfied
    assert sat(1, z_head, [0]*NROWS), "HEAD witness unsat"
    # EXEC: absorbs pt_hash
    d_exec = p3fold(d_head, pt_hash)
    z_exec = mkz(d_head, d_exec, pt_hash, 1, 0, nonces=7, noncept=8)
    assert sat(1, z_exec, [0]*NROWS), "EXEC witness unsat"
    # CLOSE: terminal, digest frozen (ISPAD=1: R0/R1 bypassed, R6 pad-neutral)
    z_close = mkz(d_exec, d_exec, 0, 2, 1)   # ispad=1: dnew==dprev
    assert sat(1, z_close, [0]*NROWS), "CLOSE witness unsat"
    # fold the chain
    Acc = (1, z_head, [0]*NROWS)
    F1, T1v, r1v, seed1 = multifold(Acc, [(1, z_exec, [0]*NROWS)])
    assert sat(*F1), "fold1 unsat"
    F2, T2v, r2v, seed2 = multifold(F1, [(1, z_close, [0]*NROWS)])
    assert sat(*F2), "fold2 unsat"
    # ---- pi_E: the WHIR-wrap commitment structure over the final accumulator ----
    evals = F2[1] + F2[2] + [F2[0]]               # z'(16) || E'(8) || u(1) = 25 elems
    # MLE domain: pad to the next power of two (the standard multilinear
    # extension; zeros beyond the true vector). CA-R146: the OOD tau width
    # MUST be log2(len(padded)) - a tau over len(evals).bit_length() indexes
    # 2^nj rows against a shorter vector (the IndexError that convicted it).
    import math
    NPAD = 1 << (len(evals) - 1).bit_length()     # 25 -> 32
    evals_p = evals + [0] * (NPAD - len(evals))
    nv_log = (NPAD - 1).bit_length()              # 32 -> 5
    C = sponge(p_, IV_SC, evals_p, MDS, RC)
    Cb = C.to_bytes(32, "little")
    def eq_table(tau):
        e = [1]
        for t in tau:
            e = [fmul(x, fsub(1, t)) for x in e] + [fmul(x, t) for x in e]
        return e
    taus, oods = [], []
    for j in range(8):
        tj = [int.from_bytes(hashlib.sha256(b"HSMA_WHIR_TAU|%d|%d" % (j,w2) + Cb).digest(), "little") % p_ for w2 in range(nv_log)]
        e = eq_table(tj)
        assert len(e) == NPAD
        oods.append(sum(fmul(e[i], evals_p[i]) for i in range(len(e))) % p_)
        taus.append(tj)
    ood_commit = sponge(p_, IV_SC, oods, MDS, RC)
    # size receipt at epoch scale
    nv = len(evals).bit_length()
    receipt = ((nv+1) + 2*nv + 1) * 32 + ((nv+1) + 3*nv + 3) * 32 + (8+1) * 32
    P("[step34] epoch chain: HEAD(d=%s) -> EXEC(d=%s) -> CLOSE, folds SAT" % (
        hex(d_head)[:12], hex(d_exec)[:12]))
    P("[step34] pi_E wrap: C + 8 OOD + ood_commit over %d evals (padded to %d)" % (len(evals), NPAD))
    P("[step34] size receipt at nv=%d: %d bytes (budget 73728: %s)" % (nv, receipt, "OK" if receipt <= 73728 else "OVER"))
    assert receipt <= 73728
    # emission
    row = lambda v: GC.row4(int(v) % p_)
    def arr(name, vals):
        return ("inline constexpr std::array<std::array<std::uint64_t, 4>, %d> %s {{\n" % (len(vals), name)
                + "".join("  { " + row(v) + " },\n" for v in vals) + "}};\n")
    one = lambda name, v: "inline constexpr std::array<std::uint64_t, 4> %s { " % name + row(v) + " };\n"
    parts = ["// HSMA :: epoch_golden.hpp - P1-13b golden (DEC-232). CANONICAL limbs.",
             "#pragma once", "#include <array>", "#include <cstdint>",
             "namespace hsma::golden {",
             one("EP_PREV", prev_digest), one("EP_PT", pt_hash), one("EP_DHEAD", d_head), one("EP_DEXEC", d_exec),
             one("EP_SEED1", seed1), one("EP_SEED2", seed2),
             arr("EP_R1", r1v), arr("EP_R2", r2v),
             arr("EP_F2_Z", F2[1]), one("EP_F2_U", F2[0]), arr("EP_F2_E", F2[2]),
             one("EP_C", C), arr("EP_OOD", oods), one("EP_OOD_COMMIT", ood_commit),
             "} // namespace hsma::golden"]
    GC.emit_hpp("epoch_golden.hpp", "\n".join(parts) + "\n")
    P("[step34][emit] epoch_golden.hpp (chain + folds + the wrap's commitments)")

_step34()

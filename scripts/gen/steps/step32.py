# HSMA :: gen/steps/step32.py - P1-12 (GAP-06 commitment folding, DEC-230).
# Mirrors cfold.hpp: pedv commitments over the GOLDEN bases (parsed from
# pedersen_golden.hpp), rho via DRBG, the multifold (the step31 mirror),
# and THE IDENTITY self-checked pre-emit (CA-R126): recommit(z',rho') ==
# W_U + r_1*C_W1. Flat emission (CA-R127). F_p everywhere (CA-R137).
import os, sys, re, hashlib
_HERE = os.path.dirname(os.path.abspath(__file__))
_sp = os.path.abspath(os.path.join(_HERE, ".."))
if _sp not in sys.path: sys.path.insert(0, _sp)
import gen_common as GC

M64 = (1 << 64) - 1

def _step32():
    P = lambda *a: print(*a, flush=True)
    hx = lambda w: int(re.search(r'0x([0-9a-fA-F]+)', w).group(1), 16)
    pt = open("generated/pallas_params_gen.hpp").read()
    pm = re.search(r'MOD\s*\{\s*\{\s*(.*?)\}\s*\}', pt, re.S)
    l = [hx(w) for w in pm.group(1).split(",")]
    p_ = l[0] | l[1] << 64 | l[2] << 128 | l[3] << 192      # F_p AND the Vesta order
    q_ = GC.load_constants()["q_vesta"]                       # the Vesta FIELD
    # golden Pedersen bases (pedv): order p, generator (-1,2) over F_q, b=5
    pg = open("generated/pedersen_golden.hpp").read()
    # positional parse (the step30-proven pattern): scan ALL rows in file order,
    # slice each array by its marker's offset. No per-name regex fragility.
    allrows = [[hx(w) for w in m.group(1).split(",")] for m in
               re.finditer(r'\{\s*(0x[0-9a-fA-F]{16}[uU][lL][lL](?:\s*,\s*0x[0-9a-fA-F]{16}[uU][lL][lL]){3})\s*\}', pg)]
    cvl = lambda r4: r4[0] | r4[1] << 64 | r4[2] << 128 | r4[3] << 192
    # STRUCTURE-anchored slice (CA-R133's lesson: layout is a contract, not a
    # guess): split the file at every array NAME marker, count rows between.
    marks = ["PALLAS_PED_ORDER", "PALLAS_PED_BASES", "PALLAS_PED_COMMIT",
             "PALLAS_PED_HOM", "PALLAS_PED_SHOM",
             "VESTA_PED_ORDER", "VESTA_PED_BASES", "VESTA_PED_COMMIT",
             "VESTA_PED_HOM", "VESTA_PED_SHOM"]
    pos = {mk: pg.find(mk) for mk in marks}
    assert all(v != -1 for v in pos.values()), "marker missing: %s" % [k for k,v in pos.items() if v==-1]
    # rows before each marker = number of row-groups in the file text before it
    rows_before = {mk: len([m2 for m2 in re.finditer(
        r'\{\s*(0x[0-9a-fA-F]{16}[uU][lL][lL](?:\s*,\s*0x[0-9a-fA-F]{16}[uU][lL][lL]){3})\s*\}',
        pg[:pos[mk]])]) for mk in marks}
    # VESTA_PED_BASES row layout: 8 rows x {h, x, y} = 3 groups each = 24 groups
    # SELF-LOCATING slice (CA-R131/133 fused): multi-group rows (m[8][4] etc.)
    # make hand-counts fragile; the H_i == [h_i]*G law picks the offset instead.
    Gv_chk = (q_ - 1, 2)
    def ec_add_chk(Pt, Qt):
        if Pt is None: return Qt
        if Qt is None: return Pt
        x1,y1 = Pt; x2,y2 = Qt
        if x1 == x2 and (y1+y2) % q_ == 0: return None
        lam = (3*x1*x1)*pow(2*y1,-1,q_) % q_ if Pt == Qt else (y2-y1)*pow(x2-x1,-1,q_) % q_
        x3 = (lam*lam - x1 - x2) % q_
        return (x3, (lam*(x1-x3) - y1) % q_)
    def ec_mul_chk(k, Pt):
        acc = None
        for bit in bin(k)[2:]:
            acc = ec_add_chk(acc, acc)
            if bit == '1': acc = ec_add_chk(acc, Pt)
        return acc
    bases = None
    for delta in (0, 1, 2):
        i0 = rows_before["VESTA_PED_BASES"] + delta
        cand = [(cvl(allrows[i0+3*i]), (cvl(allrows[i0+3*i+1]), cvl(allrows[i0+3*i+2]))) for i in range(8)]
        ok = sum(1 for i in range(8) if ec_mul_chk(cand[i][0], Gv_chk) == cand[i][1])
        P("[step32] bases offset probe +%d: %d/8 self-consistent" % (delta, ok))
        if ok == 8: bases = cand; break
    assert bases is not None, "no self-consistent bases offset found - paste this line"

    # sponge_ref (the proven extraction)
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
    nonce = 0
    while True:
        dg = hashlib.sha256(b"HSM_IV_v1|HSM_SUMCHECK_v1" + nonce.to_bytes(8,"little")).digest()
        cand = int.from_bytes(dg, "little")
        if cand < p_: IV = cand; break
        nonce += 1
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
    poseidon3 = lambda lv, rv: perm3([lv%p_, rv%p_, IV])
    fadd = lambda a,b:(a+b)%p_; fsub=lambda a,b:(a-b)%p_; fmul=lambda a,b:a*b%p_

    # ---- Vesta affine EC (the step29 oracle pattern, b=5 over F_q) ----
    def ec_add(Pt, Qt):
        if Pt is None: return Qt
        if Qt is None: return Pt
        x1,y1 = Pt; x2,y2 = Qt
        if x1 == x2 and (y1+y2) % q_ == 0: return None
        lam = (3*x1*x1)*pow(2*y1,-1,q_) % q_ if Pt == Qt else (y2-y1)*pow(x2-x1,-1,q_) % q_
        x3 = (lam*lam - x1 - x2) % q_
        return (x3, (lam*(x1-x3) - y1) % q_)
    def ec_mul(k, Pt):
        acc = None
        for bit in bin(k)[2:]:
            acc = ec_add(acc, acc)
            if bit == '1': acc = ec_add(acc, Pt)
        return acc
    Gv = (q_ - 1, 2)
    onv = lambda Pt: Pt is None or Pt[1]*Pt[1] % q_ == (pow(Pt[0],3,q_) + 5) % q_
    def pedv_commit(m8, rho):
        Cc = ec_mul(rho, Gv)
        for i in range(8): Cc = ec_add(Cc, ec_mul(m8[i] % p_, bases[i][1]))
        return Cc

    # ---- the multifold (the step31 mirror, verbatim algebra) ----
    ROWS, COLS = 4, 8
    A = [(0,0,1),(0,1,1),(1,2,1),(2,4,1),(3,5,1)]
    B = [(0,2,1),(1,3,1),(2,4,1),(3,5,1)]
    Cm = [(0,3,1),(1,7,1),(2,5,1),(3,6,1)]
    def mat_vec(M, z):
        out = [0]*ROWS
        for r_, c_, v in M: out[r_] = fadd(out[r_], fmul(v, z[c_]))
        return out
    def wit(a,b,c,d):
        z = [0]*8
        z[0]=a; z[1]=b; z[2]=c; z[4]=d
        z[3] = fmul(fadd(z[0],z[1]), z[2]); z[7] = fmul(z[2], z[3])
        z[5] = fmul(z[4], z[4]); z[6] = fmul(z[5], z[5])
        return z
    def sat(u, z, E):
        az, bz, cz = mat_vec(A,z), mat_vec(B,z), mat_vec(Cm,z)
        return all(fmul(az[i],bz[i]) == fadd(fmul(u,cz[i]), E[i]) for i in range(ROWS))
    def cross(U_, J_):
        azU,bzU,czU = mat_vec(A,U_[1]),mat_vec(B,U_[1]),mat_vec(Cm,U_[1])
        azJ,bzJ,czJ = mat_vec(A,J_[1]),mat_vec(B,J_[1]),mat_vec(Cm,J_[1])
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

    zU, zJ = wit(3,4,5,6), wit(2,1,3,4)
    U_, J_ = (1, zU, [0]*ROWS), (1, zJ, [0]*ROWS)
    assert sat(*U_) and sat(*J_)
    F1, T1v, r1v, seed1 = multifold(U_, [J_])
    assert sat(*F1) and F1[0] == fadd(1, r1v[0])
    # blindings via DRBG (deterministic, F_p)
    rho_U = int.from_bytes(hashlib.sha256(b"hsma-cfold-golden-v1|rho|U").digest(), "little") % p_
    rho_1 = int.from_bytes(hashlib.sha256(b"hsma-cfold-golden-v1|rho|1").digest(), "little") % p_
    rho_T = int.from_bytes(hashlib.sha256(b"hsma-cfold-golden-v1|rho|T").digest(), "little") % p_
    CW_U  = pedv_commit(zU, rho_U)
    CW_1  = pedv_commit(zJ, rho_1)
    Tpad  = T1v[0] + [0]*(8-ROWS)   # T1v = list of per-instance rows; take the one
    CT_1  = pedv_commit(Tpad, rho_T)
    # THE IDENTITY (CA-R126 pre-emit): recommit(z',rho') == W_U + r_1*C_W1
    rho_p = (rho_U + r1v[0]*rho_1) % p_
    Wre   = pedv_commit(F1[1], rho_p)
    Wfo   = ec_add(CW_U, ec_mul(r1v[0], CW_1))
    # ---- IDENTITY PROBE (temporary, CA-R126 evidence) ----
    print("rho_U   =", hex(rho_U)); print("rho_1   =", hex(rho_1)); print("r1      =", hex(r1v[0]))
    print("rho_p   =", hex(rho_p), "| expected (rho_U + r*rho_1) % p =", hex((rho_U + r1v[0]*rho_1) % p_))
    mism = None
    for i in range(8):
        e = (zU[i] + r1v[0]*zJ[i]) % p_
        if e != F1[1][i]: mism = (i, e, F1[1][i]); break
    print("z-fold coords:", "ALL MATCH" if mism is None else ("MISMATCH at %d: %x vs %x" % mism))
    H0 = ec_mul(bases[0][0], Gv)
    print("bases self-consistent (H0):", H0 == bases[0][1])
    if H0 != bases[0][1]:
        print("  H0 recomputed:", hex(H0[0]), hex(H0[1]))
        print("  H0 sliced    :", hex(bases[0][1][0]), hex(bases[0][1][1]))
    # direct group check of the blinding relation
    Gr1 = ec_mul(r1v[0], Gv)
    print("[rho_p]G == [rho_U]G + [r*rho_1]G:", ec_mul(rho_p, Gv) == ec_add(ec_mul(rho_U, Gv), ec_mul((r1v[0]*rho_1) % p_, Gv)))
    # also compare against C_T path: is CT_1 sanity on-curve already implied?
    print("Wre == Wfo:", Wre == Wfo)
    if Wre != Wfo:
        print("  Wre:", hex(Wre[0]), hex(Wre[1]))
        print("  Wfo:", hex(Wfo[0]), hex(Wfo[1]))
    # ---- END PROBE ----
    assert Wre == Wfo, "THE COMMITMENT FOLD IDENTITY FAILED"
    assert onv(Wre) and onv(CT_1)
    # challenge-binding negative: r+1 moves W'
    Wbad = ec_add(CW_U, ec_mul(fadd(r1v[0],1), CW_1))
    assert Wbad != Wfo
    P("[step32] commitment fold IDENTITY SELF-CHECKED (recommit == fold, exact in the order-p group)")

    row = lambda v: GC.row4(int(v) % p_)
    qrow = lambda v: GC.row4(int(v) % q_)
    def arr(name, vals, f=row):
        return ("inline constexpr std::array<std::array<std::uint64_t, 4>, %d> %s {{\n" % (len(vals), name)
                + "".join("  { " + f(v) + " },\n" for v in vals) + "}};\n")
    one = lambda name, v: "inline constexpr std::array<std::uint64_t, 4> %s { " % name + row(v) + " };\n"
    def pt(name, Pv): return (one(name+"_X", Pv[0]), one(name+"_Y", Pv[1]))
    parts = ["// HSMA :: cfold_golden.hpp - P1-12 golden (DEC-230). CANONICAL limbs.",
             "#pragma once", "#include <array>", "#include <cstdint>",
             "namespace hsma::golden {",
             one("CF_RHO_U", rho_U), one("CF_RHO_1", rho_1), one("CF_RHO_T", rho_T)]
    for nm, Pv in (("CF_CW_U", CW_U), ("CF_CW_1", CW_1), ("CF_CT_1", CT_1)):
        parts += list(pt(nm, Pv))
    parts += [one("CF_R1", r1v[0]),
              one("CF_WP_X", Wfo[0]), one("CF_WP_Y", Wfo[1]),
              one("CF_WRE_X", Wre[0]), one("CF_WRE_Y", Wre[1]),
              "} // namespace hsma::golden"]
    GC.emit_hpp("cfold_golden.hpp", "\n".join(parts) + "\n")
    P("[step32][emit] cfold_golden.hpp (rho x3, commitments x3, r1, W'/Wre)")

_step32()

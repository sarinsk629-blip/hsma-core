# HSMA :: gen/steps/step30.py - P1-10 (GAP-05 Layer 2, DEC-228).
# WHIR-class wrap golden over F_p. Bootstrap: sponge_ref is EXTRACTED from the
# monolith (the golden-pinned function, step20-proven bit-exact vs C++);
# MDS/RC parsed from poseidon_params_gen.hpp; the SUMCHECK IV by name.
# Mirrors pcs.hpp verbatim: commit= sponge, derive_points= poseidon3(C,i),
# open_1/open_2 fixed-r, lag2 with inv2=pow(2,p-2,p). WHIR per whir.hpp v2.
# Flat golden emission (array-of-[4] groups only - CA-R127 honored by design).
import os, sys, re, hashlib
_HERE = os.path.dirname(os.path.abspath(__file__))
_sp = os.path.abspath(os.path.join(_HERE, ".."))
if _sp not in sys.path: sys.path.insert(0, _sp)
import gen_common as GC

M64 = (1 << 64) - 1

def _step30():
    P = lambda *a: print(*a, flush=True)
    # --- p from pallas_params_gen.hpp ---
    pt = open("generated/pallas_params_gen.hpp").read()
    hx = lambda w: int(re.search(r'0x([0-9a-fA-F]+)', w).group(1), 16)
    pm = re.search(r'MOD\s*\{\s*\{\s*(.*?)\}\s*\}', pt, re.S)
    assert pm, "pallas MOD not found"
    l = [hx(w) for w in pm.group(1).split(",")]
    p_ = l[0] | l[1] << 64 | l[2] << 128 | l[3] << 192
    P("[step30] p = 0x%064x" % p_)
    # --- sponge_ref: the proven function, extracted from the monolith ---
    src = open("scripts/gen_constants.py").read()
    # [E1]-evidenced slice: sponge_ref is SELF-CONTAINED (helpers nested inside
    # its body). The region is exactly: "def sponge_ref" .. "def emit_poseidon".
    i0 = src.index("def sponge_ref")
    i2 = src.index("def emit_poseidon")
    region = src[i0:i2]
    compile(region, "sponge_region", "exec")   # HARD PROOF: valid Python
    import ast as _ast
    mt = _ast.parse(src)
    consts = {}
    def _try(t, node):
        try: consts[t.id] = _ast.literal_eval(node.value)
        except Exception: pass
    for node in mt.body:
        if isinstance(node, _ast.Assign):
            for t in node.targets:
                if isinstance(t, _ast.Name):
                    _try(t, node)
                elif isinstance(t, _ast.Tuple) and isinstance(node.value, _ast.Tuple):
                    for e, vv in zip(t.elts, node.value.elts):   # POSITIONAL pairing
                        if isinstance(e, _ast.Name):
                            try: consts[e.id] = _ast.literal_eval(vv)
                            except Exception: pass
    ns = {}
    for name in ("POSEIDON_ALPHA", "POSEIDON_RF", "POSEIDON_RP", "POSEIDON_T"):
        assert name in consts, "missing constant: %s (scraped: %s)" % (
            name, sorted(k for k in consts if k.startswith("POSEIDON")))
        ns[name] = consts[name]
    P("[step30] sponge_ref sliced [%d lines, compile-proven]; constants %s"
      % (region.count(chr(10)), {k: ns[k] for k in ns}))
    exec(compile(region, "sponge_region", "exec"), ns)
    sponge = ns["sponge_ref"]
    # --- MDS/RC/IV from poseidon_params_gen.hpp ---
    qt = open("generated/poseidon_params_gen.hpp").read()
    allrows = [[hx(w) for w in m2.group(1).split(",")] for m2 in
               re.finditer(r'\{\s*(0x[0-9a-fA-F]{16}[uU][lL][lL](?:\s*,\s*0x[0-9a-fA-F]{16}[uU][lL][lL]){3})\s*\}', qt)]
    assert len(allrows) >= 89, "row count short: %d" % len(allrows)
    mdsl, rcl = allrows[:9], allrows[9:89]
    if not any(any(r) for r in mdsl):
        raise SystemExit("MDS rows all zero -> p3 constants are RUNTIME-DERIVED. Paste [D6] (the p3_tables loader) and I mirror its exact derivation.")
    cv = lambda r4: r4[0] | r4[1] << 64 | r4[2] << 128 | r4[3] << 192
    MDS = [[cv(mdsl[3*r_ + c_]) for c_ in range(3)] for r_ in range(3)]
    RC = [cv(r) for r in rcl]
    # THE IV CONTRACT (iv_of, poseidon.hpp:79): sha256("HSM_IV_v1|" + TAG +
    # nonce_u64_le), first CANONICAL digest wins; derived at runtime, stored nowhere.
    def derive_iv(tag):
        nonce = 0
        while True:
            msg = b"HSM_IV_v1|" + tag.encode() + nonce.to_bytes(8, "little")
            dg = hashlib.sha256(msg).digest()
            cand = int.from_bytes(dg, "little")
            if cand < p_: return cand
            nonce += 1
    TAG = "HSM_SUMCHECK_v1"   # dom::TAG_NAMES entry for the SUMCHECK domain
    IV_SC = derive_iv(TAG)
    # self-check vs the monolith's pinned golden (if the file carries it)
    try:
        g = open("generated/poseidon_golden.hpp").read()
        mm = re.search(r'IvCase\s*\{\s*[^}]*?canon\[4\]\s*=\s*\{\s*([^}]*)\}', g)
        # scan all IvCase rows and match by position-free canonical equality
        rows = [[hx(w) for w in m2.group(1).split(",")] for m2 in
                re.finditer(r'\{\s*\d+\s*,\s*\{\s*(0x[0-9a-fA-F]{16}[uU][lL][lL](?:\s*,\s*0x[0-9a-fA-F]{16}[uU][lL][lL]){3})\s*\}\s*\}', g)]
        pinned = [cv(r) for r in rows]
        if pinned:
            ok = IV_SC in pinned
            P("[step30] IV self-check vs poseidon_golden IvCase canon values: %s" % ("MATCH" if ok else "NO MATCH (pinned set: %d)" % len(pinned)))
            if not ok: raise AssertionError("derived IV_SC not found among pinned IvCase canon values - tag mismatch?")
    except FileNotFoundError:
        P("[step30] poseidon_golden.hpp absent - IV self-check skipped (runtime-derivation contract)")
    P("[step30] MDS 3x3, RC 80, IV_SC derived per iv_of contract (tag=%s)" % TAG)
    # --- permute (the audited 4+56+4, IV lane 3) + poseidon3 ---
    def perm3(s):
        rc = 0
        def mix():
            return [sum(MDS[r_][c_] * s[c_] for c_ in range(3)) % p_ for r_ in range(3)]
        for _ in range(4):                       # full: 4 rounds x 3 RCs (12)
            for t_ in range(3): s[t_] = (s[t_] + RC[rc]) % p_; rc += 1
            s[:] = [pow(v, 5, p_) for v in s]; s[:] = mix()
        for _ in range(56):                      # partial: 56 (lane 0)
            s[0] = (s[0] + RC[rc]) % p_; rc += 1
            s[0] = pow(s[0], 5, p_); s[:] = mix()
        for _ in range(4):                       # full: 12
            for t_ in range(3): s[t_] = (s[t_] + RC[rc]) % p_; rc += 1
            s[:] = [pow(v, 5, p_) for v in s]; s[:] = mix()
        assert rc == 80, "RC consumption %d != 80 (CA-R119 arithmetic check)" % rc
        return s
    def poseidon3(l_, r_): return perm3([l_ % p_, r_ % p_, IV_SC])[0]

    NV = 10
    def drbgi(i): return int.from_bytes(hashlib.sha256(("hsma-whir-golden-v1|f|%d" % i).encode()).digest(), "little") % p_
    evals = [drbgi(i) for i in range(1 << NV)]
    C = sponge(p_, IV_SC, evals, MDS, RC)
    r1 = [poseidon3(C, j) for j in range(NV)]
    fadd = lambda a, b: (a + b) % p_
    fsub = lambda a, b: (a - b) % p_
    fmul = lambda a, b: a * b % p_
    def open_1(a, r):
        claims = [sum(a) % p_]; ev = []
        for i in range(len(r)):
            h = len(a) // 2
            p0 = sum(a[0::2]) % p_; p1 = sum(a[1::2]) % p_
            ev.append((p0, p1))
            omr = fsub(1, r[i])
            claims.append(fadd(fmul(p0, omr), fmul(p1, r[i])))
            a = [fadd(fmul(a[2*j], omr), fmul(a[2*j+1], r[i])) for j in range(h)]
        return claims, ev, (a[0] if a else 0)
    t1c, t1e, fa = open_1(list(evals), r1)
    # chain self-check
    for i in range(NV):
        omr = fsub(1, r1[i])
        assert t1c[i+1] == fadd(fmul(t1e[i][0], omr), fmul(t1e[i][1], r1[i]))
    # tau/ood/w per whir.hpp v2
    Cb = C.to_bytes(32, "little")
    def dscalar(lab, blob): return int.from_bytes(hashlib.sha256(lab.encode() + blob).digest(), "little") % p_
    taus, oods = [], []
    def eq_table(tau):
        e = [1]
        for t in tau:
            e = [fmul(x, fsub(1, t)) for x in e] + [fmul(x, t) for x in e]
        return e
    def eq_point(tau, rr):
        acc = 1
        for i in range(len(rr)):
            acc = fmul(acc, fadd(fmul(fsub(1, rr[i]), fsub(1, tau[i])), fmul(rr[i], tau[i])))
        return acc
    for j in range(8):
        tj = [dscalar("HSMA_WHIR_TAU|%d|%d" % (j, w2), Cb) for w2 in range(NV)]
        e = eq_table(tj)
        oods.append(sum(fmul(e[i], evals[i]) for i in range(len(e))) % p_)
        taus.append(tj)
    ood_commit = sponge(p_, IV_SC, oods, MDS, RC)
    Ob = ood_commit.to_bytes(32, "little")
    ws = [dscalar("HSMA_WHIR_W|%d" % j, Ob) for j in range(8)]
    Wbar = [0] * (1 << NV)
    for j in range(8):
        e = eq_table(taus[j])
        for i in range(len(e)): Wbar[i] = fadd(Wbar[i], fmul(ws[j], e[i]))
    C2 = sponge(p_, IV_SC, evals + Wbar, MDS, RC)
    r2 = [poseidon3(C2, j) for j in range(NV)]
    i2 = pow(2, p_ - 2, p_)
    def lag2(rv, p0, p1, p2):
        rm1, rm2 = fsub(rv, 1), fsub(rv, 2)
        return fadd(fadd(fmul(p0, fmul(fmul(rm1, rm2), i2)),
                         fmul(p1, fmul(rv, fsub(2, rv)))),
                    fmul(p2, fmul(fmul(rv, rm1), i2)))
    def open_2(a, b, r):
        claims = [sum(fmul(x, y) for x, y in zip(a, b)) % p_]; ev = []
        for i in range(len(r)):
            h = len(a) // 2
            p0 = sum(fmul(a[2*j], b[2*j]) for j in range(h)) % p_
            p1 = sum(fmul(a[2*j+1], b[2*j+1]) for j in range(h)) % p_
            a2 = [fsub(fmul(2, a[2*j+1]), a[2*j]) for j in range(h)]
            b2 = [fsub(fmul(2, b[2*j+1]), b[2*j]) for j in range(h)]
            p2 = sum(fmul(x, y) for x, y in zip(a2, b2)) % p_
            ev.append((p0, p1, p2))
            claims.append(lag2(r[i], p0, p1, p2))
            omr = fsub(1, r[i])
            a = [fadd(fmul(a[2*j], omr), fmul(a[2*j+1], r[i])) for j in range(h)]
            b = [fadd(fmul(b[2*j], omr), fmul(b[2*j+1], r[i])) for j in range(h)]
        return claims, ev, (a[0] if a else 0), (b[0] if b else 0)
    t2c, t2e, fa2, fb2 = open_2(list(evals), list(Wbar), r2)
    Wc = list(Wbar)
    for i in range(NV):
        h = len(Wc) // 2; omr = fsub(1, r2[i])
        Wc = [fadd(fmul(Wc[2*j], omr), fmul(Wc[2*j+1], r2[i])) for j in range(h)]
    fb_true = Wc[0] if Wc else 0
    # THE verifier-independent identity: fb == sum_j w_j*eq(tau_j, r2)
    fbv = sum(fmul(ws[j], eq_point(taus[j], r2)) for j in range(8)) % p_
    assert fb2 == fb_true == fbv, "fb identity violated"
    P("[step30] wrap SELF-CHECKED: T1 nv=%d, T2 d=2, fb==fb_true==sum w_j*eq(tau_j,r2)" % NV)
    nv20 = 20
    receipt = ((nv20+1) + 2*nv20 + 1) * 32 + ((nv20+1) + 3*nv20 + 3) * 32 + (8+1) * 32
    P("[step30] size receipt at nv=20: %d bytes (budget 73728: %s)" % (receipt, "OK" if receipt <= 73728 else "OVER"))
    assert receipt <= 73728
    # emission - FLAT: every object is an array of [4] groups (CA-R127 by design)
    row = lambda v: GC.row4(int(v) % p_)
    def arr(name, vals):
        return ("inline constexpr std::array<std::array<std::uint64_t, 4>, %d> %s {{\n" % (len(vals), name)
                + "".join("  { " + row(v) + " },\n" for v in vals) + "}};\n")
    one = lambda name, v: "inline constexpr std::array<std::uint64_t, 4> %s { " % name + row(v) + " };\n"
    parts = ["// HSMA :: whir_golden.hpp - P1-10 golden (DEC-228). CANONICAL limbs.",
             "// evals[i] = sha256(\"hsma-whir-golden-v1|f|i\") LE % p; seed string is the contract.",
             "#pragma once", "#include <array>", "#include <cstdint>",
             "namespace hsma::golden {",
             "inline constexpr unsigned WHIR_NV = %du;" % NV,
             "inline constexpr unsigned WHIR_K = 8u;",
             one("WHIR_C", C),
             arr("WHIR_T1_CLAIMS", t1c),
             arr("WHIR_T1_EVALS", [x for ev in t1e for x in ev[:2]]),
             one("WHIR_T1_FA", fa),
             one("WHIR_C2", C2),
             arr("WHIR_T2_CLAIMS", t2c),
             arr("WHIR_T2_EVALS", [x for ev in t2e for x in ev]),
             one("WHIR_T2_FA", fa2), one("WHIR_T2_FB", fb2), one("WHIR_T2_FB_TRUE", fb_true),
             arr("WHIR_TAU", [t for tj in taus for t in tj]),
             arr("WHIR_OOD", oods),
             one("WHIR_OOD_COMMIT", ood_commit),
             arr("WHIR_W", ws),
             "} // namespace hsma::golden"]
    GC.emit_hpp("whir_golden.hpp", "\n".join(parts) + "\n")
    P("[step30][emit] whir_golden.hpp (T1+T2+tau/ood/w, nv=%d)" % NV)

_step30()

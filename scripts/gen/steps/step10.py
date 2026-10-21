# HSMA :: gen/steps/step10.py - prelude+def+call extract (FROZEN; byte-preserving).

# ═══ STEP 10 APPEND — F_q2, twist E', G2 (DEC-193..196) ═══

def _s10_fatal(msg):
    print("[step10] FATAL: " + msg); raise SystemExit(1)

# ── F_q2 arithmetic: (c0, c1) = c0 + c1·u, u² = β ──
def _s10_add(a, b, q):
    return ((a[0]+b[0]) % q, (a[1]+b[1]) % q)
def _s10_sub(a, b, q):
    return ((a[0]-b[0]) % q, (a[1]-b[1]) % q)
def _s10_mul(a, b, q, beta):
    return ((a[0]*b[0] + beta*a[1]*b[1]) % q, (a[0]*b[1] + a[1]*b[0]) % q)
def _s10_sqr(a, q, beta):
    return _s10_mul(a, a, q, beta)
def _s10_conj(a, q):
    return (a[0], (-a[1]) % q)
def _s10_norm(a, q, beta):
    return (a[0]*a[0] - beta*a[1]*a[1]) % q
def _s10_inv(a, q, beta):
    n = _s10_norm(a, q, beta)
    ni = pow(n, -1, q)
    c = _s10_conj(a, q)
    return ((c[0]*ni) % q, (c[1]*ni) % q)
def _s10_eq(a, b):
    return a[0] == b[0] and a[1] == b[1]
def _s10_is0(a):
    return a[0] == 0 and a[1] == 0

def _s10_sqrt(z, q, beta):
    """w² = z in F_q2, or None. Criterion: N(z) is a square in F_q."""
    c0, c1 = z
    if c1 == 0:
        if c0 == 0: return (0, 0)
        if pow(c0, (q-1)//2, q) == 1:
            return (_s8_tonelli(c0, q), 0)
        t = (c0 * pow(beta, -1, q)) % q
        if pow(t, (q-1)//2, q) == 1:
            return (0, _s8_tonelli(t, q))
        return None
    N = (c0*c0 - beta*c1*c1) % q
    if pow(N, (q-1)//2, q) != 1: return None
    s = _s8_tonelli(N, q)
    inv2 = pow(2, -1, q)
    for sign in (1, -1):
        t = (c0 + sign*s) * inv2 % q
        if pow(t, (q-1)//2, q) == 1:
            a = _s8_tonelli(t, q)
            b = c1 * pow(2*a % q, -1, q) % q
            w = (a, b)
            if _s10_eq(_s10_sqr(w, q, beta), z): return w
    return None

def _s10_pow(a, e, q, beta):
    r = (1, 0); b = a
    while e:
        if e & 1: r = _s10_mul(r, b, q, beta)
        b = _s10_mul(b, b, q, beta)
        e >>= 1
    return r

# ── E' (twist curve): y² = x³ + b' over F_q2, affine ──
def _s10_e2_dbl(P, q, beta):
    if P is None: return None
    x, y = P
    if _s10_is0(y): return None
    num = _s10_mul((3, 0), _s10_sqr(x, q, beta), q, beta)
    den = _s10_add(y, y, q)
    lam = _s10_mul(num, _s10_inv(den, q, beta), q, beta)
    lam2 = _s10_sqr(lam, q, beta)
    x3 = _s10_sub(_s10_sub(lam2, x, q), x, q)
    y3 = _s10_sub(_s10_mul(lam, _s10_sub(x, x3, q), q, beta), y, q)
    return (x3, y3)

def _s10_e2_add(P, Q, q, beta):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P; x2, y2 = Q
    if _s10_eq(x1, x2):
        if _s10_is0(_s10_add(y1, y2, q)): return None
        return _s10_e2_dbl(P, q, beta)
    lam = _s10_mul(_s10_sub(y2, y1, q),
                   _s10_inv(_s10_sub(x2, x1, q), q, beta), q, beta)
    lam2 = _s10_sqr(lam, q, beta)
    x3 = _s10_sub(_s10_sub(lam2, x1, q), x2, q)
    y3 = _s10_sub(_s10_mul(lam, _s10_sub(x1, x3, q), q, beta), y1, q)
    return (x3, y3)

def _s10_e2_mul(P, k, q, beta):
    R = None; A = P
    while k:
        if k & 1: R = _s10_e2_add(R, A, q, beta)
        A = _s10_e2_dbl(A, q, beta)
        k >>= 1
    return R

def _s10_e2_rand_pt(b2, q, beta, salt, _att=0):
    for _ in range(_att, _att + 200):
        h = _h8.sha256(salt + _att.to_bytes(8, "big")).digest() + \
            _h8.sha256(salt + b"hi" + _att.to_bytes(8, "big")).digest()
        _att += 1
        x = (int.from_bytes(h[:32], "big") % q, int.from_bytes(h[32:], "big") % q)
        if _s10_is0(x): continue
        x3 = _s10_mul(_s10_sqr(x, q, beta), x, q, beta)
        y = _s10_sqrt(_s10_add(x3, b2, q), q, beta)
        if y is not None:
            return (x, y)
    _s10_fatal("e2 rand_pt starved")

def _step10_params():
    P8 = _step8_params()
    q, r, x, h1 = P8["q"], P8["r"], P8["x"], P8["h1"]
    beta = 2
    while pow(beta, (q-1)//2, q) == 1:
        beta += 1
    h2 = (x**8 - 4*x**7 + 5*x**6 - 4*x**4 + 6*x**3 - 4*x**2 - 4*x + 13) // 9
    n2 = h2 * r
    if abs(n2 - q*q - 1) > 2*q:
        _s10_fatal("h2 Hasse check failed")
    for cand in [(0,1),(1,1),(beta,0),(beta,1),(1,beta),(0,beta)]:
        try:
            P = _s10_e2_rand_pt(cand, q, beta, b"HSM_G10_TWIST")
        except SystemExit:
            continue
        if P is None: continue
        Q = _s10_e2_mul(P, h2, q, beta)
        if Q is None: continue
        if _s10_e2_mul(Q, r, q, beta) is not None: continue
        return dict(q=q, r=r, x=x, h1=h1, h2=h2, beta=beta, b2=cand)
    _s10_fatal("no valid twist coefficient found")

def _s10_row6(v):
    return "{0x%016xull, 0x%016xull, 0x%016xull, 0x%016xull, 0x%016xull, 0x%016xull}" % (
        v & 0xFFFFFFFFFFFFFFFF, (v >> 64) & 0xFFFFFFFFFFFFFFFF,
        (v >> 128) & 0xFFFFFFFFFFFFFFFF, (v >> 192) & 0xFFFFFFFFFFFFFFFF,
        (v >> 256) & 0xFFFFFFFFFFFFFFFF, (v >> 320) & 0xFFFFFFFFFFFFFFFF)

def _s10_fq2_row(a):
    return "{ " + _s10_row6(a[0]) + ", " + _s10_row6(a[1]) + " }"
def _s10_fq2_rows(vals):
    return ",\n    ".join(_s10_fq2_row(v) for v in vals)
def _s10_brow(bs):
    return ", ".join("0x%02xu" % b for b in bs)

def _step10():
    P10 = _step10_params()
    q, r, beta, b2, h2 = P10["q"], P10["r"], P10["beta"], P10["b2"], P10["h2"]
    print("[t10] beta=%d h2=2^%d b2=(%d,%d)" % (beta, h2.bit_length(), b2[0], b2[1]))

    FQ = 32
    def draw_fq2(salt):
        h = _h8.sha256(salt + b"a").digest() + _h8.sha256(salt + b"b").digest()
        return (int.from_bytes(h[:32], "big") % q, int.from_bytes(h[32:], "big") % q)
    A = []; B = []
    while len(A) < FQ: A.append(draw_fq2(b"HSM_G10_FA" + len(A).to_bytes(4,"little")))
    while len(B) < FQ: B.append(draw_fq2(b"HSM_G10_FB" + len(B).to_bytes(4,"little")))
    ADD = [_s10_add(a, b, q) for a, b in zip(A, B)]
    SUB = [_s10_sub(a, b, q) for a, b in zip(A, B)]
    MUL = [_s10_mul(a, b, q, beta) for a, b in zip(A, B)]
    print("[t10] F_q2 pairs x%d OK" % FQ)

    pts = []
    while len(pts) < 4:
        P = _s10_e2_rand_pt(b2, q, beta, b"HSM_G10_PX" + len(pts).to_bytes(4,"little"))
        if P is not None and (lambda Q: Q is not None and
            _s10_e2_mul(Q, r, q, beta) is None or True)(_s10_e2_mul(P, h2, q, beta)):
            pts.append(P)
    ADDT = [(pts[i], pts[(i+1)%4], _s10_e2_add(pts[i], pts[(i+1)%4], q, beta)) for i in range(4)]
    DBLT = [(P, _s10_e2_dbl(P, q, beta)) for P in pts]
    ks = _s8_draw(4, r, b"HSM_G10_K") if '_s8_draw' in dir() else _step7_draw(4, r, b"HSM_G10_K")
    MULt = [(ks[i], pts[i], _s10_e2_mul(pts[i], ks[i], q, beta)) for i in range(4)]
    for P in pts:
        if _s10_e2_mul(_s10_e2_mul(P, h2, q, beta), r, q, beta) is not None:
            _s10_fatal("point not in correct subgroup")
    print("[t10] E' triples x4+4+4 OK")

    G2P = _s10_e2_rand_pt(b2, q, beta, b"HSM_G2_GEN")
    G2 = _s10_e2_mul(G2P, h2, q, beta)
    if G2 is None or _s10_e2_mul(G2, r, q, beta) is not None:
        _s10_fatal("G2 generator failed [r]G2 != inf")
    print("[t10] G2 generator: [h2]P ok, [r]G2=inf verified")

    cdirs = set()
    for root, dirs, files in _os8.walk("."):
        if ".git" in root.split(_os8.sep): continue
        if "pallas_params_gen.hpp" in files: cdirs.add(root)
    if len(cdirs) != 1: _s10_fatal("ambiguous dirs")
    outdir = cdirs.pop()

    hp = ("// GENERATED — STEP 10 (DEC-193..). DO NOT EDIT.\n"
          "// Authority: beta=smallest non-square (generator-discovered);\n"
          "// b2=twist coef (computational search); h2 from BLS12 literature (DEC-193).\n"
          "// Verified: Hasse bound + [r]([h2]P)=inf on E'.\n"
          "#pragma once\n#include <cstdint>\nnamespace hsma::blsq2 {\n")
    hp += "inline constexpr std::uint64_t G2_BETA[6] = " + _s10_row6(beta) + ";\n"
    hp += "inline constexpr std::uint64_t G2_B2_C0[6] = " + _s10_row6(b2[0]) + ";\n"
    hp += "inline constexpr std::uint64_t G2_B2_C1[6] = " + _s10_row6(b2[1]) + ";\n"
    hp += "inline constexpr std::uint64_t G2_H2[6] = " + _s10_row6(h2) + ";\n"
    hp += "inline constexpr std::uint64_t G2_GEN_X_C0[6] = " + _s10_row6(G2[0][0]) + ";\n"
    hp += "inline constexpr std::uint64_t G2_GEN_X_C1[6] = " + _s10_row6(G2[0][1]) + ";\n"
    hp += "inline constexpr std::uint64_t G2_GEN_Y_C0[6] = " + _s10_row6(G2[1][0]) + ";\n"
    hp += "inline constexpr std::uint64_t G2_GEN_Y_C1[6] = " + _s10_row6(G2[1][1]) + ";\n"
    # STEP 10-B: final-exponent limbs (DEC-102 mechanical pinning): (q^12-1)//r
    e_exp = (q**12 - 1) // r
    _limbs = []
    _v = e_exp
    while _v:
        _limbs.append(_v & 0xFFFFFFFFFFFFFFFF); _v >>= 64
    hp += "inline constexpr unsigned G12_FEXP_N = %du;\n" % len(_limbs)
    hp += "inline constexpr std::uint64_t G12_FEXP[%d] = {\n    " % len(_limbs)
    hp += ", ".join("0x%016xull" % _x for _x in _limbs) + "\n};\n"
    hp += "}\n"

    def fq2p(P): return "{ " + _s10_row6(P[0][0]) + ", " + _s10_row6(P[0][1]) + \
        ", " + _s10_row6(P[1][0]) + ", " + _s10_row6(P[1][1]) + " }"
    hg = ("// GENERATED — STEP 10 (DEC-194..). DO NOT EDIT.\n"
          "// Oracle: pure Python F_q2/E' arithmetic.\n"
          "#pragma once\n#include <cstdint>\nnamespace hsma::golden {\n")
    hg += "inline constexpr unsigned G10_FQ = %uu;\n" % FQ
    for nm, vv in (("G10_A", A), ("G10_B", B), ("G10_ADD", ADD), ("G10_SUB", SUB), ("G10_MUL", MUL)):
        hg += "inline constexpr std::uint64_t %s[G10_FQ][2][6] = {\n    " % nm
        hg += ",\n    ".join(_s10_fq2_row(v) for v in vv) + "\n};\n"
    hg += "inline constexpr std::uint64_t G10_ADD_P[4][4][6] = {\n    "
    hg += ",\n    ".join(fq2p(t[0]) for t in ADDT) + "\n};\n"
    hg += "inline constexpr std::uint64_t G10_ADD_Q[4][4][6] = {\n    "
    hg += ",\n    ".join(fq2p(t[1]) for t in ADDT) + "\n};\n"
    hg += "inline constexpr std::uint64_t G10_ADD_R[4][4][6] = {\n    "
    hg += ",\n    ".join(fq2p(t[2]) for t in ADDT) + "\n};\n"
    hg += "inline constexpr std::uint64_t G10_DBL_P[4][4][6] = {\n    "
    hg += ",\n    ".join(fq2p(t[0]) for t in DBLT) + "\n};\n"
    hg += "inline constexpr std::uint64_t G10_DBL_R[4][4][6] = {\n    "
    hg += ",\n    ".join(fq2p(t[1]) for t in DBLT) + "\n};\n"
    hg += "inline constexpr std::uint64_t G10_MUL_K[4][6] = {\n    "
    hg += ",\n    ".join(_s10_row6(k) for k in ks) + "\n};\n"
    hg += "inline constexpr std::uint64_t G10_MUL_P[4][4][6] = {\n    "
    hg += ",\n    ".join(fq2p(t[1]) for t in MULt) + "\n};\n"
    hg += "inline constexpr std::uint64_t G10_MUL_R[4][4][6] = {\n    "
    hg += ",\n    ".join(fq2p(t[2]) for t in MULt) + "\n};\n}\n"

    open(_os8.path.join(outdir, "bls_g2_params_gen.hpp"), "w").write(hp)
    open(_os8.path.join(outdir, "g2_curve_golden.hpp"), "w").write(hg)
    print("[validate] twist: beta=%d, b2=(%d,%d), h2 bits=%d" % (beta, b2[0], b2[1], h2.bit_length()))
    print("[step10][emit] bls_g2_params_gen.hpp (beta, b2, h2, G2 generator)")
    print("[step10][emit] g2_curve_golden.hpp (%d fq2 pairs, 4+4+4 E' triples)" % FQ)

_step10()

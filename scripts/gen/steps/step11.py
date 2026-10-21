# HSMA :: gen/steps/step11.py - prelude+def+call extract (FROZEN; byte-preserving).

# ═══ STEP 10B APPEND — F_q12 tower, Miller loop, BLS verify (DEC-197..) ═══
# Tower: F_q2 → F_q6[v]/(v³-γ) → F_q12[w]/(w²-v), γ=b'=(5,1), δ=v.
# Elegant: w⁶ = v³ = γ = b' → w IS the twist map parameter.

def _s12_fatal(msg):
    print("[step10b] FATAL: " + msg); raise SystemExit(1)

# ── F_q6: (d0, d1, d2), each d_i ∈ F_q2, v³ = γ ──
def _s12_6add(a, b, q):
    return (_s10_add(a[0], b[0], q), _s10_add(a[1], b[1], q), _s10_add(a[2], b[2], q))
def _s12_6sub(a, b, q):
    return (_s10_sub(a[0], b[0], q), _s10_sub(a[1], b[1], q), _s10_sub(a[2], b[2], q))
def _s12_6mul(a, b, q, beta, gamma):
    # (a0+a1·v+a2·v²)(b0+b1·v+b2·v²), v³=γ
    t00 = _s10_mul(a[0], b[0], q, beta)
    t01 = _s10_mul(a[0], b[1], q, beta)
    t02 = _s10_mul(a[0], b[2], q, beta)
    t10 = _s10_mul(a[1], b[0], q, beta)
    t11 = _s10_mul(a[1], b[1], q, beta)
    t12 = _s10_mul(a[1], b[2], q, beta)
    t20 = _s10_mul(a[2], b[0], q, beta)
    t21 = _s10_mul(a[2], b[1], q, beta)
    t22 = _s10_mul(a[2], b[2], q, beta)
    c0 = _s10_add(t00, _s10_mul(gamma, _s10_add(t12, t21, q), q, beta), q)
    c1 = _s10_add(_s10_add(t01, t10, q), _s10_mul(gamma, t22, q, beta), q)
    c2 = _s10_add(_s10_add(t02, t11, q), t20, q)
    return (c0, c1, c2)
def _s12_6eq(a, b):
    return _s10_eq(a[0], b[0]) and _s10_eq(a[1], b[1]) and _s10_eq(a[2], b[2])

# ── F_q12: (e0, e1), each e_i ∈ F_q6, w² = δ = v ──
# δ as F_q6 element: v = (0, 1, 0) = ((0,0),(1,0),(0,0))
def _s12_delta():
    return (((0,0),(1,0),(0,0)))

def _s12_add(a, b, q):
    return (_s12_6add(a[0], b[0], q), _s12_6add(a[1], b[1], q))
def _s12_sub(a, b, q):
    return (_s12_6sub(a[0], b[0], q), _s12_6sub(a[1], b[1], q))
def _s12_mul(a, b, q, beta, gamma):
    # (e0 + e1·w)(f0 + f1·w) = (e0·f0 + δ·e1·f1) + (e0·f1 + e1·f0)·w
    delta = _s12_delta()
    t0 = _s12_6mul(a[0], b[0], q, beta, gamma)
    t1 = _s12_6mul(delta, _s12_6mul(a[1], b[1], q, beta, gamma), q, beta, gamma)
    t2 = _s12_6mul(a[0], b[1], q, beta, gamma)
    t3 = _s12_6mul(a[1], b[0], q, beta, gamma)
    return (_s12_6add(t0, t1, q), _s12_6add(t2, t3, q))
def _s12_sqr(a, q, beta, gamma):
    return _s12_mul(a, a, q, beta, gamma)
def _s12_one():
    return ((((1,0),(0,0),(0,0)), ((0,0),(0,0),(0,0))))
def _s12_eq(a, b):
    return _s12_6eq(a[0], b[0]) and _s12_6eq(a[1], b[1])
def _s12_pow(a, e, q, beta, gamma):
    r = _s12_one(); b = a
    while e:
        if e & 1: r = _s12_mul(r, b, q, beta, gamma)
        b = _s12_mul(b, b, q, beta, gamma)
        e >>= 1
    return r

def _s12_inv(a, q, beta, gamma):
    # Tower-norm inverse: a^-1 = conj(a)/N(a); N(a) = e0^2 - v*e1^2 in F_q6;
    # F_q6 inverse via cubic adjugate/det (det in F_q2, inverted by _s10_inv).
    # ~2000x faster than Fermat q^12-2. Verified: a*inv(a) == 1.
    e0, e1 = a
    e0sq = _s12_6mul(e0, e0, q, beta, gamma)
    e1sq = _s12_6mul(e1, e1, q, beta, gamma)
    ve1sq = _s12_6mul(((0,0),(1,0),(0,0)), e1sq, q, beta, gamma)
    n = _s12_6sub(e0sq, ve1sq, q)
    n0, n1, n2 = n
    n0sq = _s10_mul(n0, n0, q, beta)
    n1sq = _s10_mul(n1, n1, q, beta)
    n2sq = _s10_mul(n2, n2, q, beta)
    n1n2 = _s10_mul(n1, n2, q, beta)
    n0n1 = _s10_mul(n0, n1, q, beta)
    n0n2 = _s10_mul(n0, n2, q, beta)
    g = gamma
    g2 = _s10_mul(g, g, q, beta)
    det = _s10_add(_s10_add(_s10_mul(n0, n0sq, q, beta),
                            _s10_mul(g, _s10_mul(n1, n1sq, q, beta), q, beta), q),
                   _s10_mul(g2, _s10_mul(n2, n2sq, q, beta), q, beta), q)
    trip = _s10_mul((3, 0), _s10_mul(g, _s10_mul(n0, n1n2, q, beta), q, beta), q, beta)
    det = _s10_sub(det, trip, q)
    det_inv = _s10_inv(det, q, beta)
    m0 = _s10_sub(n0sq, _s10_mul(g, n1n2, q, beta), q)
    m1 = _s10_sub(_s10_mul(g, n2sq, q, beta), n0n1, q)
    m2 = _s10_sub(n1sq, n0n2, q)
    n_inv = (_s10_mul(m0, det_inv, q, beta),
             _s10_mul(m1, det_inv, q, beta),
             _s10_mul(m2, det_inv, q, beta))
    zero6 = ((0,0),(0,0),(0,0))
    neg_e1 = _s12_6sub(zero6, e1, q)
    return _s12_mul((e0, neg_e1), (n_inv, zero6), q, beta, gamma)

# ── Twist map: ψ(x',y') = (x'/w², y'/w³) = (x'/v, y'/(v·w)) ──
# w² = v, w³ = v·w. Since v is an F_q6 element, x'/v is in F_q12.
def _s12_twist(xq, yq, q, beta, gamma):
    """xq, yq ∈ F_q2 (E' point). Returns E(F_q12) point."""
    # x' / v: x' is F_q2 ⊂ F_q6. v = (0,1,0). Compute in F_q12.
    # We embed x' into F_q12 as (x'_as_fq6, zero) and divide by (v, zero).
    # Actually: x'/v in F_q12. v has an inverse in F_q12 (since v | w², and w is invertible).
    # v⁻¹ = w⁴/v⁵ = ... let's just use the big-exponent inverse.
    v_fq6 = ((0,0),(1,0),(0,0))
    v_fq12 = (v_fq6, ((0,0),(0,0),(0,0)))  # v as F_q12 element (e0=v, e1=0)
    v_inv = _s12_inv(v_fq12, q, beta, gamma)
    xq_fq6 = (xq, (0,0), (0,0))  # F_q2 → F_q6 embedding
    yq_fq6 = (yq, (0,0), (0,0))
    xq_fq12 = (xq_fq6, ((0,0),(0,0),(0,0)))  # F_q6 → F_q12 embedding
    yq_fq12 = (yq_fq6, ((0,0),(0,0),(0,0)))
    # ψ(x',y') = (x'/w², y'/w³) = (x'/v, y'/(v·w))
    # x'/v: multiply xq_fq12 by v_inv
    new_x = _s12_mul(xq_fq12, v_inv, q, beta, gamma)
    # y'/(v·w): y'/(v·w) = (y'/v)·(1/w) = (y'·v_inv)·w⁻¹
    # w⁻¹: w·w = v, so w⁻¹ = w/v... actually w⁻¹ = w³/w⁴ = w³/(w²)² = w³/v²
    # Simpler: w⁻¹ = w·(w²)⁻¹·(w²)⁻¹ = w·v⁻²... 
    # Actually: w·w⁻¹ = 1. w⁻¹ = w⁵/w⁶ = w⁵/γ (since w⁶=γ)
    # Or just: w⁻¹ = w^(q^12-2)
    w_fq12 = (((0,0),(0,0),(0,0)), ((1,0),(0,0),(0,0)))  # (0, 1) in F_q12
    w_inv = _s12_inv(w_fq12, q, beta, gamma)
    yv = _s12_mul(yq_fq12, v_inv, q, beta, gamma)
    new_y = _s12_mul(yv, w_inv, q, beta, gamma)
    return new_x, new_y

def _s12_e_add(P, Q, q, beta, gamma):
    """P, Q ∈ E(F_q12) affine or None. y²=x³+1."""
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P; x2, y2 = Q
    if _s12_eq(x1, x2):
        if _s12_eq(_s12_add(y1, y2, q), (((0,0),(0,0),(0,0)),((0,0),(0,0),(0,0)))):  # CA-R52: zero, not one
            return None
        # Doubling
        three = (((3,0),(0,0),(0,0)),((0,0),(0,0),(0,0)))
        num = _s12_mul(_s12_mul(three, x1, q, beta, gamma), x1, q, beta, gamma)
        den = _s12_add(y1, y1, q)
        den_inv = _s12_inv(den, q, beta, gamma)
        lam = _s12_mul(num, den_inv, q, beta, gamma)
    else:
        num = _s12_sub(y2, y1, q)
        den = _s12_sub(x2, x1, q)
        den_inv = _s12_inv(den, q, beta, gamma)
        lam = _s12_mul(num, den_inv, q, beta, gamma)
    lam2 = _s12_sqr(lam, q, beta, gamma)
    x3 = _s12_sub(_s12_sub(lam2, x1, q), x2, q)
    y3 = _s12_sub(_s12_mul(lam, _s12_sub(x1, x3, q), q, beta, gamma), y1, q)
    return (x3, y3)

def _s12_e_mul(P, k, q, beta, gamma):
    R = None; A = P
    while k:
        if k & 1: R = _s12_e_add(R, A, q, beta, gamma)
        A = _s12_e_add(A, A, q, beta, gamma)
        k >>= 1
    return R

def _s12_miller(P, Q_twisted, q, beta, gamma, r):
    """Tate pairing Miller loop. P ∈ E(F_q), Q_twisted ∈ E(F_q12).
    Returns f_{r,P}(Q) ∈ F_q12."""
    # Embed P into E(F_q12)
    def embed(x_fq):
        return (((x_fq, 0), (0,0), (0,0)), ((0,0),(0,0),(0,0)))
    Px = embed(P[0]); Py = embed(P[1])
    Qx, Qy = Q_twisted
    f = _s12_one()
    T = (Px, Py)  # T = P
    for i in range(r.bit_length() - 2, -1, -1):
        # Tangent at T
        three = (((3,0),(0,0),(0,0)),((0,0),(0,0),(0,0)))
        num = _s12_mul(three, _s12_mul(T[0], T[0], q, beta, gamma), q, beta, gamma)
        den = _s12_add(T[1], T[1], q)
        den_inv = _s12_inv(den, q, beta, gamma)
        lam = _s12_mul(num, den_inv, q, beta, gamma)
        # Line: l(x,y) = (y - Ty) - λ(x - Tx), evaluated at Q
        l = _s12_sub(_s12_sub(Qy, T[1], q), _s12_mul(lam, _s12_sub(Qx, T[0], q), q, beta, gamma), q)
        f = _s12_mul(_s12_sqr(f, q, beta, gamma), l, q, beta, gamma)
        # T = 2T
        lam2 = _s12_sqr(lam, q, beta, gamma)
        Tx3 = _s12_sub(_s12_sub(lam2, T[0], q), T[0], q)
        Ty3 = _s12_sub(_s12_mul(lam, _s12_sub(T[0], Tx3, q), q, beta, gamma), T[1], q)
        T = (Tx3, Ty3)
        if (r >> i) & 1 and i > 0:  # i==0 add is the VERTICAL line x-x_P (den=0);
                                    # its value lies in F_q6 and dies in the final
                                    # exponentiation (r | q^6+1) - skip: denominator elim.
            # Chord through T and P
            num = _s12_sub(Py, T[1], q)
            den = _s12_sub(Px, T[0], q)
            den_inv = _s12_inv(den, q, beta, gamma)
            lam = _s12_mul(num, den_inv, q, beta, gamma)
            l = _s12_sub(_s12_sub(Qy, T[1], q), _s12_mul(lam, _s12_sub(Qx, T[0], q), q, beta, gamma), q)
            f = _s12_mul(f, l, q, beta, gamma)
            lam2 = _s12_sqr(lam, q, beta, gamma)
            Tx3 = _s12_sub(_s12_sub(lam2, T[0], q), Px, q)
            Ty3 = _s12_sub(_s12_mul(lam, _s12_sub(T[0], Tx3, q), q, beta, gamma), T[1], q)
            T = (Tx3, Ty3)
    return f

def _s12_pairing(P, Q, q, beta, gamma, r, b2):
    """Full reduced Tate pairing. P ∈ E(F_q) (G1), Q ∈ E'(F_q2) (G2)."""
    Qx, Qy = _s12_twist(Q[0], Q[1], q, beta, gamma)
    f = _s12_miller(P, (Qx, Qy), q, beta, gamma, r)
    # Final exponentiation: f^((q^12-1)/r)
    e = (q**12 - 1) // r
    return _s12_pow(f, e, q, beta, gamma)

def _step10b():
    P10 = _step10_params()
    q, r, beta, b2, h2 = P10["q"], P10["r"], P10["beta"], P10["b2"], P10["h2"]
    gamma = b2  # tower γ = b' = (5,1)
    print("[t10b] tower: gamma=(%d,%d), delta=v (w²=v, w⁶=γ)" % (gamma[0], gamma[1]))

    # Verify tower: w⁶ = γ
    w = (((0,0),(0,0),(0,0)), ((1,0),(0,0),(0,0)))
    w6 = _s12_pow(w, 6, q, beta, gamma)
    if not _s12_6eq(w6[0], (gamma, (0,0), (0,0))) or not _s12_6eq(w6[1], ((0,0),(0,0),(0,0))):
        _s12_fatal("w⁶ ≠ γ")
    print("[t10b] w⁶ = γ verified")

    # Verify twist: ψ maps E' to E
    Q_test = _s10_e2_rand_pt(b2, q, beta, b"HSM_G12_TWIST_TEST")
    Qx, Qy = _s12_twist(Q_test[0], Q_test[1], q, beta, gamma)
    # Check on E: y² = x³ + 1
    y2 = _s12_sqr(Qy, q, beta, gamma)
    x3 = _s12_mul(_s12_sqr(Qx, q, beta, gamma), Qx, q, beta, gamma)
    one = _s12_one()
    rhs = _s12_add(x3, one, q)
    if not _s12_eq(y2, rhs):
        _s12_fatal("twist map: ψ(Q) not on E")
    print("[t10b] twist map: ψ(Q) on E verified")

    # Bilinearity: e([a]P, [b]Q) = e(P,Q)^(ab)
    # Use P = G1 gen, Q = G2 gen, a=b=2
    P_gen = _step8_params()["gen"]  # G1 generator (affine canonical, integers; P8 dict)
    Q_gen = _s10_e2_mul(_s10_e2_rand_pt(b2, q, beta, b"HSM_G12_Q"), h2, q, beta)

    a, b = 2, 3
    Pa = _s8_mul(P_gen, a, q)       # [a]P in E(F_q)
    Qb = _s10_e2_mul(Q_gen, b, q, beta)  # [b]Q in E'(F_q2)

    e_ab = _s12_pairing(Pa, Qb, q, beta, gamma, r, b2)
    e_1 = _s12_pairing(P_gen, Q_gen, q, beta, gamma, r, b2)
    if _s12_eq(e_1, _s12_one()):
        _s12_fatal("pairing degenerate: e(G1, G2) == 1")
    print("[t10b] non-degenerate: e(G1, G2) != 1")
    e_ab_expected = _s12_pow(e_1, a * b, q, beta, gamma)

    if not _s12_eq(e_ab, e_ab_expected):
        _s12_fatal("bilinearity failed: e([a]P,[b]Q) ≠ e(P,Q)^(ab)")
    print("[t10b] bilinearity verified: e([2]P,[3]Q) == e(P,Q)⁶")

    # BLS verification: e(σ, G2gen) == e(H(m), Y)
    # Use the step-7 committee secret S
    # -- BLS verification law: retires the harness-secret law (DEC-191 deferral) --
    # e(sigma, G2gen) == e(H(m), Y)  with sigma = [S]H(m), Y = [S]G2gen
    h1 = P10["h1"]
    co = _step7_draw(15, r, b"HSM_G7_DRBG_v1P")
    polys = [co[i*3:(i+1)*3] for i in range(5)]
    S = sum(polys[i][0] for i in range(5)) % r          # step-7 committee secret
    share = [[_s7_pe(polys[i], j, r) for j in range(1, 6)] for i in range(5)]
    Sj = [sum(share[i][j-1] for i in range(5)) % r for j in range(1, 6)]
    lam = _s9_lam([2, 3, 5], r)

    G2g = _s10_e2_mul(_s10_e2_rand_pt(b2, q, beta, b"HSM_G2_GEN"), h2, q, beta)
    m_pre = b"HSM_BLS_VERIFY_V1"
    Hm = _s9_h2g1(m_pre, q, h1)
    sigma = _s8_mul(Hm, S, q)
    Y = _s10_e2_mul(G2g, S, q, beta)

    lhs = _s12_pairing(sigma, G2g, q, beta, gamma, r, b2)
    rhs = _s12_pairing(Hm, Y, q, beta, gamma, r, b2)
    if not _s12_eq(lhs, rhs):
        _s12_fatal("BLS law failed: e(sigma, G2gen) != e(H(m), Y)")
    print("[t10b] BLS LAW VERIFIED: e([S]H, G2gen) == e(H, [S]G2gen)  (secret-free)")

    sigma_t = _s8_mul(Hm, (S + 1) % r, q)
    lhs_t = _s12_pairing(sigma_t, G2g, q, beta, gamma, r, b2)
    if _s12_eq(lhs_t, rhs):
        _s12_fatal("tampered sigma verified - soundness broken")
    print("[t10b] tampered sigma rejected (soundness)")

    parts = [_s8_mul(Hm, Sj[j-1], q) for j in (2, 3, 5)]
    sigma_agg = None
    for l_, pj in zip(lam, parts):
        addend = _s8_mul(pj, l_, q)
        sigma_agg = addend if sigma_agg is None else _s8_add(sigma_agg, addend, q)
    lhs_a = _s12_pairing(sigma_agg, G2g, q, beta, gamma, r, b2)
    if not _s12_eq(lhs_a, rhs):
        _s12_fatal("threshold aggregate verify failed")
    print("[t10b] threshold t-of-n aggregate VERIFIED (partials + Lagrange -> e == e)")

    # -- Golden set + emission: pairing_golden.hpp (DEC-197..199) --
    print("[t10b] generating pairing goldens...")

    def fq12_row(a):
        parts = []
        for half in a:
            for comp in half:
                parts.append(_s10_row6(comp[0]))
                parts.append(_s10_row6(comp[1]))
        return "{ " + ", ".join(parts) + " }"

    def row_pt(P):
        return "{ " + _s10_row6(P[0]) + ", " + _s10_row6(P[1]) + " }"

    def row_e2(Q):
        return "{ " + _s10_row6(Q[0][0]) + ", " + _s10_row6(Q[0][1]) + \
               ", " + _s10_row6(Q[1][0]) + ", " + _s10_row6(Q[1][1]) + " }"

    def pairing(P, Q):
        return _s12_pairing(P, Q, q, beta, gamma, r, b2)

    def miller_f(P, Q):
        Qx, Qy = _s12_twist(Q[0], Q[1], q, beta, gamma)
        return _s12_miller(P, (Qx, Qy), q, beta, gamma, r)

    MIL = []
    while len(MIL) < 8:
        i = len(MIL)
        k = _s8_draw(1, r, b"HSM_G12_MP" + i.to_bytes(4, "little"))[0]
        Pm = _s8_mul(P_gen, k, q)
        Qm = _s10_e2_mul(_s10_e2_rand_pt(b2, q, beta, b"HSM_G12_MQ" + i.to_bytes(4, "little")), h2, q, beta)
        MIL.append((Pm, Qm, miller_f(Pm, Qm)))
    print("[t10b] miller goldens x8 OK")

    PAP = []
    while len(PAP) < 4:
        i = len(PAP)
        k = _s8_draw(1, r, b"HSM_G12_PP" + i.to_bytes(4, "little"))[0]
        Pm = _s8_mul(P_gen, k, q)
        Qm = _s10_e2_mul(_s10_e2_rand_pt(b2, q, beta, b"HSM_G12_PQ" + i.to_bytes(4, "little")), h2, q, beta)
        PAP.append((Pm, Qm, pairing(Pm, Qm)))
    print("[t10b] pairing goldens x4 OK")

    m2 = b"HSM_BLS_VERIFY_V2"
    H2 = _s9_h2g1(m2, q, h1)
    sigma2 = _s8_mul(H2, S, q)
    assert _s12_eq(pairing(sigma2, G2g), pairing(H2, Y)), "BLS case 3 failed"
    BLS = [(sigma, Hm, Y, True), (sigma_agg, Hm, Y, True), (sigma2, H2, Y, True),
           (sigma_t, Hm, Y, False)]
    print("[t10b] BLS cases x4 (3 pass + 1 tamper) OK")

    cdirs = set()
    for root, dirs, files in _os8.walk("."):
        if ".git" in root.split(_os8.sep): continue
        if "pallas_params_gen.hpp" in files: cdirs.add(root)
    if len(cdirs) != 1: _s12_fatal("ambiguous dirs")
    outdir = cdirs.pop()

    hg = ("// GENERATED - STEP 10-B (DEC-197..199). DO NOT EDIT.\n"
          "// Oracle: pure Python F_q12 tower + Miller + reduced Tate pairing.\n"
          "// Fq12 layout: 12 groups x 6 limbs = (e0.c0.x, e0.c0.y, e0.c1.x, e0.c1.y,\n"
          "// e0.c2.x, e0.c2.y, e1.c0.x, ..., e1.c2.y) - canonical integers.\n"
          "#pragma once\n#include <cstdint>\nnamespace hsma::golden {\n")
    hg += "inline constexpr unsigned G12_MILLER = 8u;\n"
    hg += "inline constexpr std::uint64_t G12_MILLER_P[8][2][6] = {\n    " + ",\n    ".join(row_pt(t[0]) for t in MIL) + "\n};\n"
    hg += "inline constexpr std::uint64_t G12_MILLER_Q[8][4][6] = {\n    " + ",\n    ".join(row_e2(t[1]) for t in MIL) + "\n};\n"
    hg += "inline constexpr std::uint64_t G12_MILLER_F[8][12][6] = {\n    " + ",\n    ".join(fq12_row(t[2]) for t in MIL) + "\n};\n"
    hg += "inline constexpr unsigned G12_PAIR = 4u;\n"
    hg += "inline constexpr std::uint64_t G12_PAIR_P[4][2][6] = {\n    " + ",\n    ".join(row_pt(t[0]) for t in PAP) + "\n};\n"
    hg += "inline constexpr std::uint64_t G12_PAIR_Q[4][4][6] = {\n    " + ",\n    ".join(row_e2(t[1]) for t in PAP) + "\n};\n"
    hg += "inline constexpr std::uint64_t G12_PAIR_E[4][12][6] = {\n    " + ",\n    ".join(fq12_row(t[2]) for t in PAP) + "\n};\n"
    hg += "inline constexpr unsigned G12_BLS = 4u;\n"
    hg += "inline constexpr std::uint64_t G12_BLS_S[4][2][6] = {\n    " + ",\n    ".join(row_pt(t[0]) for t in BLS) + "\n};\n"
    hg += "inline constexpr std::uint64_t G12_BLS_H[4][2][6] = {\n    " + ",\n    ".join(row_pt(t[1]) for t in BLS) + "\n};\n"
    hg += "inline constexpr std::uint64_t G12_BLS_Y[4][4][6] = {\n    " + ",\n    ".join(row_e2(t[2]) for t in BLS) + "\n};\n"
    hg += "inline constexpr bool G12_BLS_OK[4] = { %s };\n" % ", ".join("true" if t[3] else "false" for t in BLS)
    hg += "inline constexpr std::uint64_t G12_THR_S[3][2][6] = {\n    " + ",\n    ".join(row_pt(pp) for pp in parts) + "\n};\n"
    hg += "inline constexpr std::uint64_t G12_THR_LAM[3][4] = {\n    " + ",\n    ".join(_s7_row(l_) for l_ in lam) + "\n};\n"
    hg += "inline constexpr std::uint64_t G12_THR_AGG[2][6] = " + row_pt(sigma_agg) + ";\n"
    hg += "inline constexpr std::uint64_t G12_THR_H[2][6] = " + row_pt(Hm) + ";\n"
    hg += "inline constexpr std::uint64_t G12_THR_Y[4][6] = " + row_e2(Y) + ";\n"
    hg += "inline constexpr std::uint64_t G12_E1[12][6] = " + fq12_row(e_1) + ";\n"
    hg += "inline constexpr std::uint64_t G12_E1_Q[4][6] = " + row_e2(Q_gen) + ";\n}\n"
    open(_os8.path.join(outdir, "pairing_golden.hpp"), "w").write(hg)
    print("[step10b][emit] pairing_golden.hpp (miller x8, pairings x4, BLS x4, threshold x1, e_1)")

    return dict(q=q, r=r, beta=beta, gamma=gamma, b2=b2,
                P_gen=P_gen, Q_gen=Q_gen, e_1=e_1, bilinear=True,
                S=S, Sj=Sj, lam=lam, G2g=G2g, Hm=Hm, sigma=sigma, Y=Y,
                MIL=MIL, PAP=PAP, BLS=BLS)

_step10b()

# ═══ STEP 11 APPEND — sim_beacon retirement: consensus goldens consume HSM_BEACON_V1 (DEC-200) ═══
import hashlib as _h11

def _step11():
    P8 = _step8_params()
    q, r, h1 = P8["q"], P8["r"], P8["h1"]
    co = _step7_draw(15, r, b"HSM_G7_DRBG_v1P")
    polys = [co[i*3:(i+1)*3] for i in range(5)]
    share = [[_s7_pe(polys[i], j, r) for j in range(1, 6)] for i in range(5)]
    S = [sum(share[i][j-1] for i in range(5)) % r for j in range(1, 6)]
    lam = _s9_lam([2, 3, 5], r)

    def _chain11(e, prev):
        pre = b"HSM_BEACON_V1" + e.to_bytes(8, "little") + prev
        H = _s9_h2g1(pre, q, h1)
        sg = None
        for l, j in zip(lam, [2, 3, 5]):
            sg = _s8_add(sg, _s8_mul(_s8_mul(H, S[j-1], q), l, q), q)
        return _h11.sha256(_s9_ser(sg)).digest()

    b1r = _chain11(CONS_EPOCH, bytes(32))       # HSM_BEACON_V1 genesis @ CONS_EPOCH
    b2r = _chain11(CONS_EPOCH + 1, b1r)         # chain @ CONS_EPOCH+1

    # value-injection: RefAuto.__init__ resolves _cons_static via module globals,
    # so the patch redirects it; then re-invoke the UNMODIFIED emission machinery.
    _orig_cs = _cons_static
    def _cons_static_real():
        vid, wt, T, wr, txh, txa, cid, _b1, _b2 = _orig_cs()
        return vid, wt, T, wr, txh, txa, cid, b1r, b2r
    globals()["_cons_static"] = _cons_static_real

    cdirs = set()
    for root, dirs, files in _os8.walk("."):
        if ".git" in root.split(_os8.sep): continue
        if "pallas_params_gen.hpp" in files: cdirs.add(root)
    if len(cdirs) != 1:
        print("[step11] FATAL: ambiguous dirs"); raise SystemExit(1)
    emit_consensus_scenario(cdirs.pop())
    print("[step11] sim_beacon RETIRED from the golden path (DEC-200):")
    print("[step11] consensus_golden.hpp re-emitted with HSM_BEACON_V1 over the G7 committee")

_step11()

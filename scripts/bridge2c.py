import faulthandler, json, re, sys
faulthandler.dump_traceback_later(240, exit=True)   # any hang names itself in 4 min
st = json.load(open("build/bridge_stage1.json"))
q = int(st["q"]); N = int(st["N"]); s_q = int(st["s_q"])
rho = (int(st["rho0"]), int(st["rho1"]))
BS = (-5) % q
ONE = (1, 0)
def P(*a):
    print(*a, flush=True)
def sadd(a,b): return ((a[0]+b[0])%q, (a[1]+b[1])%q)
def ssub(a,b): return ((a[0]-b[0])%q, (a[1]-b[1])%q)
def smul(a,b): return ((a[0]*b[0] + BS*a[1]*b[1]) % q, (a[0]*b[1]+a[1]*b[0]) % q)
def sinv(a):
    n = (a[0]*a[0] - BS*a[1]*a[1]) % q
    ni = pow(n, -1, q)
    return (a[0]*ni % q, (-a[1])*ni % q)
def spow(a,e):
    R = ONE
    while e:
        if e & 1: R = smul(R, a)
        a = smul(a, a); e >>= 1
    return R
def fq_sqrt(a):
    t2q = 0; mq = q - 1
    while mq % 2 == 0: mq //= 2; t2q += 1
    z = 2
    while pow(z, (q-1)//2, q) != q-1: z += 1
    x = pow(a, (mq+1)//2, q); b = pow(a, mq, q); c = pow(z, mq, q); i = t2q
    while b != 1:
        j = 0; bb = b
        while bb != 1: bb = bb*bb % q; j += 1
        c = pow(z, 1 << (i-j-1), q)
        x = x*c % q; b = b*c*c % q; i = j
    return x
def f2_sqrt(a):
    """(x+yu)^2 = (x^2+5y^2, 2xy) with u^2=+5. Derivation: let r^2 = a0^2-5a1^2
    (diff-norm) OR r^2 = a0^2+5a1^2 (sum-norm, if -1 factors). Try BOTH norms,
    BOTH roots of each, BOTH sign patterns - the self-check (R^2==a) arbitrates."""
    a0, a1 = a
    import math
    tried = 0
    for norm_sign in (-5, +5):
        na = (a0*a0 + norm_sign*a1*a1) % q
        r = fq_sqrt(na)
        if r is None: continue
        for rr in {r, (q-r) % q}:
            x2 = (a0 + rr) * pow(2, -1, q) % q
            if x2 == 0:
                # x=0 case: y^2 = a0/5 and 2xy=a1 forces a1==0
                if a1 % q != 0: continue
                continue
            if pow(x2, (q-1)//2, q) != 1: continue
            x = fq_sqrt(x2)
            for xs in {x, (q-x) % q}:
                if xs == 0: continue
                y = a1 * pow(2*xs, -1, q) % q
                R = (xs, y)
                tried += 1
                if smul(R, R) == a: return R
    print("[f2_sqrt] exhausted: tried", tried, "candidates, norm family both signs")
    return None
P("[stage] starting: sqrt(rho)")
c = f2_sqrt(rho)
P("[C1] c = sqrt(rho) ok:", c is not None and smul(c, c) == rho)
assert c is not None
t3 = 0; m3 = N
while m3 % 3 == 0: m3 //= 3; t3 += 1
P("[stage] t3 =", t3)
e = pow(3, -1, m3)
w = spow(c, e)
P("[C2] w^3 == c:", smul(smul(w, w), w) == c)
P("[C2b] w^6 == rho:", smul(smul(smul(w, w), w), smul(smul(w, w), w)) == rho)
s_hdr = open("build/generated/bls_q_params_gen.hpp").read()
def hdr6(txt, name):
    mm = re.search(name + r"\[6\]\s*=\s*\{([^}]*)\}", txt)
    ls = [int(x.strip().rstrip("uUlL"), 16) for x in mm.group(1).split(",")]
    return sum(l << (64*i) for i, l in enumerate(ls))
g2s = open("build/generated/bls_g2_params_gen.hpp").read()
def g2hdr6(name):
    mm = re.search(name + r"\[6\]\s*=\s*\{([^}]*)\}", g2s)
    ls = [int(x.strip().rstrip("uUlL"), 16) for x in mm.group(1).split(",")]
    return sum(l << (64*i) for i, l in enumerate(ls))
def Phi(a): return (a[0], (a[1]*s_q) % q)
Xo = (g2hdr6("G2_GEN_X_C0"), g2hdr6("G2_GEN_X_C1"))
Yo = (g2hdr6("G2_GEN_Y_C0"), g2hdr6("G2_GEN_Y_C1"))
w2 = smul(w, w); w3 = smul(w2, w)
Xw = smul(Phi(Xo), w2); Yw = smul(Phi(Yo), w3)
P("[stage] psi point built")
B2_SPEC = (0, 155198655607781456406391640216936120121836107652948796323930557600032281009004493664981332883744016074664192874906)
on_spec = smul(Yw, Yw) == sadd(smul(smul(Xw, Xw), Xw), B2_SPEC)
P("[D1] psi(our gen) on the SPEC curve:", on_spec)
def e_add(Pt, Qt):
    if Pt is None: return Qt
    if Qt is None: return Pt
    (x1,y1),(x2,y2) = Pt, Qt
    if x1 == x2 and y1 == ssub((0,0), y2): return None
    if Pt == Qt:
        num = smul((3,0), smul(x1, x1)); den = sinv(sadd(y1, y1))
    else:
        num = ssub(y2, y1); den = sinv(ssub(x2, x1))
    lam = smul(num, den)
    x3 = ssub(ssub(smul(lam, lam), x1), x2)
    return (x3, ssub(smul(lam, ssub(x1, x3)), y1))
def e_mul(k, Pt):
    R = None; A = Pt
    while k:
        if k & 1: R = e_add(R, A)
        A = e_add(A, A); k >>= 1
    return R
P("[stage] e_mul ladder starting (253 bits)")
inf1 = e_mul(r_val, (Xw, Yw))
P("[D2] [r]psi(our gen) == inf:", inf1 is None)
d = open("build/ref_curves_g2.rs").read()
vals = {}
for nm in ("G2_GENERATOR_X_C0", "G2_GENERATOR_X_C1", "G2_GENERATOR_Y_C0", "G2_GENERATOR_Y_C1"):
    m = re.search(r'const %s: Fq = MontFp!\("([0-9]+)"\);' % nm, d)
    vals[nm] = int(m.group(1)) if m else None
if all(v is not None for v in vals.values()):
    AX = (vals["G2_GENERATOR_X_C0"], vals["G2_GENERATOR_X_C1"])
    AY = (vals["G2_GENERATOR_Y_C0"], vals["G2_GENERATOR_Y_C1"])
    P("[E1] ark gen on spec curve:", smul(AY, AY) == sadd(smul(smul(AX, AX), AX), B2_SPEC))
    P("[stage] ark e_mul ladder starting")
    inf2 = e_mul(r_val, (AX, AY))
    P("[E2] [r]ark gen == inf:", inf2 is None)
else:
    P("[E] MontFp parse failed - paste: grep -n 'G2_GENERATOR_X_C0' build/ref_curves_g2.rs")
json.dump({"s_q": str(s_q), "w0": str(w[0]), "w1": str(w[1])},
          open("build/bridge_stage2.json", "w"))
P("[stage2] checkpoint saved -> build/bridge_stage2.json")

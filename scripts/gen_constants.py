#!/usr/bin/env python3
import argparse, hashlib, math, sys, random, re

CURVES = {
    "pallas": {
        "p": 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001,
        "b": -17, "pair_of": "vesta"
    },
    "vesta": {
        "p": 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001,
        "b": 17, "pair_of": "pallas"
    },
}

MONT_W = 256
N_LIMBS = 4

POSEIDON_T, POSEIDON_RF, POSEIDON_RP, POSEIDON_ALPHA = 3, 8, 56, 5
POSEIDON_RC_COUNT = (POSEIDON_RF // 2) * POSEIDON_T * 2 + POSEIDON_RP
POSEIDON_SCHEDULE = "HSMA-P3-v1"

DOMAIN_TAGS = [
    "HSM_MSSC_VOTE_v1","HSM_ORDER_v1","HSM_DEC_SHARE_v2","HSM_TX_AUTH_v1",
    "HSM_BEACON_MSG_v1","HSM_BEACON_OUT_v1","HSM_CERT_v1","HSM_BIND_v1",
    "HSM_SORTITION_v1","HSM_PEERSEED_v1","HSM_FOLD_v1","HSM_CYCLEFOLD_v1",
    "HSM_DIGEST_v1","HSM_PT_v1","HSM_MODEL_v1","HSM_DEM_v1","HSM_TXID_v1",
    "HSM_AEAD_AES","HSM_AEAD_CHACHA",
    "IV_STATE_NODE","IV_STATE_LEAF","IV_ORDER","IV_DECREE","IV_WEIGHT",
    "IV_CONTACT","IV_REVOCATION","IV_TABLE_REG","IV_SEED","IV_IDENT",
    "IV_CONFLICT","IV_TXID","IV_BREAKER","IV_FIDELITY",
]

def miller_rabin(n, rounds=64):
    if n < 2: return False
    for sp in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n % sp == 0: return n == sp
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2; r += 1
    rng = random.Random(0x48534D41)
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1: break
        else: return False
    return True

def two_adicity(n):
    k = 0
    while n % 2 == 0: n //= 2; k += 1
    return k

def has_affine_point(p, b):
    for x in range(1, 64):
        rhs = (pow(x, 3, p) + b) % p
        if rhs == 0 or pow(rhs, (p - 1) // 2, p) == 1: return True
    return False

def fatal(msg): print(f"[FATAL] {msg}", file=sys.stderr); sys.exit(1)

def validate(name, spec):
    p = spec["p"]
    if p % 2 == 0: fatal(f"{name}: modulus even")
    if not (250 <= p.bit_length() <= 255): fatal(f"{name}: unexpected bit length {p.bit_length()}")
    if not miller_rabin(p): fatal(f"{name}: primality FAILED")
    ta = two_adicity(p - 1)
    if ta < 32: fatal(f"{name}: 2-adicity {ta} < 32")
    if not has_affine_point(p, spec["b"] % p): fatal(f"{name}: no affine point")
    log2_p = math.log2(p)
    print(f"[validate] {name}: prime ✓  bits={p.bit_length()}  2-adicity={ta}  log2(p)={log2_p:.12f}")
    return {"p": p, "log2": log2_p}

def derive_montgomery(p):
    R = 1 << MONT_W
    inv = pow(p, -1, 1 << 64)
    n0 = (-inv) % (1 << 64)
    rr = (R * R) % p
    r_mod = R % p
    assert (n0 * p) % (1 << 64) == (1 << 64) - 1, "n0 identity failed"
    return {"inv": inv, "n0": n0, "rr": rr, "r_mod": r_mod}

def limbs(x, n=N_LIMBS):
    out = []
    for _ in range(n):
        out.append(x & ((1 << 64) - 1)); x >>= 64
    return out

def L4(x):
    return "{ " + ", ".join(f"0x{v:016x}ULL" for v in limbs(x)) + " }"

def emit_header(name, v, outdir):
    p = v["p"]; m = derive_montgomery(p)
    ph = f"{p:064x}"
    body = f"""// GENERATED FILE - {name}_params_gen.hpp
#pragma once
#include <array>
#include <cstdint>
namespace hsma::{name}_gen {{
inline constexpr std::array<std::uint64_t, 4> MOD {{ {L4(p)} }} ;
inline constexpr std::uint64_t INV = 0x{m['n0']:016x}ULL;
inline constexpr std::array<std::uint64_t, 4> RR {{ {L4(m['rr'])} }} ;
inline constexpr std::array<std::uint64_t, 4> R_ONE {{ {L4(m['r_mod'])} }} ;
static_assert((INV * MOD[0]) == ~0ULL, "n0 identity failed in C++");
static_assert(MOD[0] & 1ULL, "modulus must be odd");
}} // namespace hsma::{name}_gen
"""
    path = f"{outdir}/{name}_params_gen.hpp"
    with open(path, "w") as f: f.write(body)
    print(f"[emit] {path}")
    print(f"[flags] -DHSMA_{name.upper()}_N0=0x{m['n0']:016x} -DHSMA_{name.upper()}_P_HI=0x{limbs(p)[3]:016x}")

def emit_field_vectors(outdir):
    rng = random.Random(0xA6F10)
    p = CURVES["pallas"]["p"]
    edges = [0, 1, 2, p - 1, p - 2, (1 << 256) % p, (1 << 64) - 1]
    cases = []
    vals = edges + [rng.randrange(p) for _ in range(96)]
    for a in vals:
        for b in vals[:24]: cases.append((a, b))
    lines = ["// GENERATED - field_golden.hpp", "#pragma once", "#include <array>", "#include <cstdint>", "namespace hsma::golden {", "struct FieldCase { std::uint64_t a[4], b[4], sum[4], diff[4], prod[4]; };", f"inline constexpr std::array<FieldCase, {len(cases)}> FIELD_CASES {{{{"]
    for a, b in cases:
        lines.append("  { " + ", ".join([L4(a), L4(b), L4((a+b)%p), L4((a-b)%p), L4((a * b * pow(1<<256, -1, p)) % p)]) + " },")
    lines += ["}};", "}"]
    path = f"{outdir}/field_golden.hpp"
    with open(path, "w") as f: f.write("\n".join(lines) + "\n")
    print(f"[emit] {path} ({len(cases)} cases)")

def emit_rnte_vectors(outdir):
    rng = random.Random(0xBEEF)
    def ref(mag, neg, s):
        half, q, r = 1 << (s - 1), mag >> s, mag & ((1 << s) - 1)
        b = 1 if (r > half or (r == half and (q & 1))) else 0
        y = q + b
        SAT = (1 << 31) - 1
        if y > SAT: return (SAT if not neg else -SAT, True)
        return (-y if neg else y, False)
    cases = []
    for s in (16, 32):
        for mag in (0, 1, (1<<s)-1, 1<<(s-1), (1<<(s-1))-1, (1<<(s-1))+1, (1<<(s-1))+2, rng.randrange(1<<62)):
            for neg in (False, True):
                cases.append((mag, neg, s, *ref(mag, neg, s)))
    lines = ["// GENERATED - rnte_golden.hpp", "#pragma once", "#include <array>", "#include <cstdint>", "namespace hsma::golden {", "struct RnteCase { std::uint64_t mag; bool neg; unsigned s; std::int32_t want; bool want_sat; };", f"inline constexpr std::array<RnteCase, {len(cases)}> RNTE_CASES {{{{"]
    for mag, neg, s, want, sat in cases:
        lines.append(f"  {{ {mag}ULL, {str(neg).lower()}, {s}, {want}, {str(sat).lower()} }},")
    lines += ["}};", "}"]
    path = f"{outdir}/rnte_golden.hpp"
    with open(path, "w") as f: f.write("\n".join(lines) + "\n")
    print(f"[emit] {path} ({len(cases)} cases)")

def _drbg(seed, nbytes):
    out, ctr = bytearray(), 0
    while len(out) < nbytes:
        out += hashlib.sha256(seed + ctr.to_bytes(8, "little")).digest()
        ctr += 1
    return bytes(out[:nbytes])

def derive_rc(p, n, label):
    seed = b"HSM_POSEIDON_RC_v1|" + POSEIDON_SCHEDULE.encode() + b"|" + label.encode()
    stream, out, off = _drbg(seed, n * 48 + 64), [], 0
    while len(out) < n:
        v = int.from_bytes(stream[off:off + 40], "big")
        off += 40
        if v < p: out.append(v)
    return out

def _det3(M, p):
    return (M[0][0]*(M[1][1]*M[2][2]-M[1][2]*M[2][1]) - M[0][1]*(M[1][0]*M[2][2]-M[1][2]*M[2][0]) + M[0][2]*(M[1][0]*M[2][1]-M[1][1]*M[2][0])) % p

def derive_mds(p, t):
    xs, ys = list(range(1, t + 1)), list(range(t + 1, 2 * t + 1))
    M = [[pow(xs[i] + ys[j], -1, p) for j in range(t)] for i in range(t)]
    for i in range(t):
        for j in range(t): assert M[i][j] % p != 0, "MDS entry zero"
    for i1 in range(t):
        for i2 in range(i1 + 1, t):
            for j1 in range(t):
                for j2 in range(j1 + 1, t):
                    d = (M[i1][j1]*M[i2][j2] - M[i1][j2]*M[i2][j1]) % p
                    assert d != 0, "2x2 minor singular"
    assert _det3(M, p) != 0, "3x3 minor singular"
    return M

def iv_derive(p, tag):
    nonce = 0
    while True:
        h = hashlib.sha256(b"HSM_IV_v1|" + tag.encode() + nonce.to_bytes(8, "little")).digest()
        v = int.from_bytes(h, "little")
        if v < p: return v
        nonce += 1

def poseidon3_ref(p, iv, l, r, MDS, RC):
    sbox = lambda x: pow(x, POSEIDON_ALPHA, p)
    def mix(s): return [sum(MDS[i][j] * s[j] for j in range(POSEIDON_T)) % p for i in range(POSEIDON_T)]
    s, k = [l, r, iv], 0
    for _ in range(POSEIDON_RF // 2):
        s = [(a + c) % p for a, c in zip(s, RC[k:k + 3])]; k += 3
        s = [sbox(x) for x in s]; s = mix(s)
    for _ in range(POSEIDON_RP):
        s = [(a + RC[k]) % p if i == 0 else a for i, a in enumerate(s)]; k += 1
        s[0] = sbox(s[0]); s = mix(s)
    for _ in range(POSEIDON_RF // 2):
        s = [(a + c) % p for a, c in zip(s, RC[k:k + 3])]; k += 3
        s = [sbox(x) for x in s]; s = mix(s)
    return s[0]

def sponge_ref(p, iv, elems, MDS, RC):
    s, idx, n = [0, 0, iv], 0, 0
    st = {"s": s, "idx": 0}
    def _perm_state(s):
        sbox = lambda x: pow(x, POSEIDON_ALPHA, p)
        def mix(s): return [sum(MDS[i][j] * s[j] for j in range(3)) % p for i in range(3)]
        k = 0
        for _ in range(POSEIDON_RF // 2):
            s = [(a + c) % p for a, c in zip(s, RC[k:k+3])]; k += 3
            s = [sbox(x) for x in s]; s = mix(s)
        for _ in range(POSEIDON_RP):
            s = [(a + RC[k]) % p if i == 0 else a for i, a in enumerate(s)]; k += 1
            s[0] = sbox(s[0]); s = mix(s)
        for _ in range(POSEIDON_RF // 2):
            s = [(a + c) % p for a, c in zip(s, RC[k:k+3])]; k += 3
            s = [sbox(x) for x in s]; s = mix(s)
        return s
    def perm(): st["s"] = _perm_state(st["s"])
    def absorb(x):
        st["s"][st["idx"]] = (st["s"][st["idx"]] + x) % p
        st["idx"] += 1
        if st["idx"] == 2:
            perm(); st["idx"] = 0
    for e in elems: absorb(e)
    n = len(elems); absorb(n); absorb(1)
    if st["idx"] != 0: perm()
    return st["s"][0]

def emit_poseidon(outdir):
    p = CURVES["pallas"]["p"]
    MDS = derive_mds(p, POSEIDON_T)
    RC = derive_rc(p, POSEIDON_RC_COUNT, "PALLAS")
    print(f"[poseidon] MDS proven (all minors nonsingular); {len(RC)} RCs derived")
    enums = [re.sub(r"[^A-Za-z0-9]", "_", t) for t in DOMAIN_TAGS]
    
    body = ["// GENERATED FILE - poseidon_params_gen.hpp", "#pragma once", "#include <array>", "#include <cstdint>", "namespace hsma::p3_gen {", f"inline constexpr unsigned T={POSEIDON_T}, RF={POSEIDON_RF}, RP={POSEIDON_RP}, RC_COUNT={POSEIDON_RC_COUNT};"]
    mds_rows = []
    for i in range(3):
        mds_rows.append("{{ " + ", ".join(L4(MDS[i][j]) for j in range(3)) + " }}")
    body.append("inline constexpr std::array<std::array<std::array<std::uint64_t,4>,3>,3> MDS_CANON{{ " + ", ".join(mds_rows) + " }};")
    body.append(f"inline constexpr std::array<std::array<std::uint64_t,4>,{POSEIDON_RC_COUNT}> RC_CANON{{{{")
    for c in RC: body.append("  " + L4(c) + ",")
    body.append("}};")
    body.append("} // namespace hsma::p3_gen")
    
    reg = ["// GENERATED FILE - domain_registry_gen.hpp", "#pragma once", "#include <array>", "#include <cstdint>", "#include <string_view>", "namespace hsma::dom {", "enum class Dom : std::uint8_t{" + ",".join(enums) + ",COUNT};", f"inline constexpr std::array<std::string_view,{len(DOMAIN_TAGS)}> TAG_NAMES{{{{"]
    for t in DOMAIN_TAGS: reg.append(f'  "{t}",')
    reg.extend(["}};", "static_assert(TAG_NAMES.size() == static_cast<size_t>(Dom::COUNT));", "} // namespace hsma::dom"])
    
    for path, lines in ((f"{outdir}/poseidon_params_gen.hpp", body), (f"{outdir}/domain_registry_gen.hpp", reg)):
        with open(path, "w") as f: f.write("\n".join(lines) + "\n")
        print(f"[emit] {path}")

def emit_poseidon_goldens(outdir):
    rng = random.Random(0xD00D)
    p = CURVES["pallas"]["p"]
    MDS = derive_mds(p, POSEIDON_T)
    RC = derive_rc(p, POSEIDON_RC_COUNT, "PALLAS")
    ivs = [iv_derive(p, t) for t in DOMAIN_TAGS]
    
    lines = ["// GENERATED FILE - poseidon_golden.hpp", "#pragma once", "#include <array>", "#include <cstdint>", "namespace hsma::golden {", "struct IvCase { std::uint16_t tag; std::uint64_t canon[4]; };", f"inline constexpr std::array<IvCase,{len(ivs)}> IV_CASES{{{{"]
    for i, v in enumerate(ivs): lines.append(f"  {{ {i}, {L4(v)} }},")
    lines.append("}};")
    
    lines.extend(["struct P3Case { std::uint16_t tag; std::uint64_t l[4], r[4], out[4]; };", "inline constexpr std::array<P3Case,48> P3_CASES{{"])
    for _ in range(48):
        tag = rng.randrange(len(ivs))
        l, r = rng.randrange(p), rng.randrange(p)
        o = poseidon3_ref(p, ivs[tag], l, r, MDS, RC)
        lines.append(f"  {{ {tag}, {L4(l)}, {L4(r)}, {L4(o)} }},")
    lines.append("}};")
    
    lines.extend(["struct SpCase { std::uint16_t tag; unsigned n; bool fixed2; std::uint64_t a[4], b[4], out[4]; };", "inline constexpr std::array<SpCase,14> SPONGE_CASES{{"])
    specs = [(0,[]),(0,[1]),(1,[2]),(2,[3,4]),(3,[5]),(4,[6,7]),(5,[8,9,10]),(6,[11]),(7,[12,13]),(8,[14,15,16,17]),(9,[18]),(10,[]),(11,[19,20]),(31,[21,22])]
    for i,(tag,els) in enumerate(specs):
        els = els or ([rng.randrange(p)] if i % 2 else [])
        es = []
        for k_idx in range(len(els)):
            if k_idx < 2:
                es.append(rng.randrange(p))
            else:
                es.append(k_idx)
        o = sponge_ref(p, ivs[tag], es, MDS, RC)
        a = es[0] if len(es) > 0 else 0
        b = es[1] if len(es) > 1 else 0
        lines.append(f"  {{ {tag}, {len(es)}, {str(len(es)==2).lower()}, {L4(a)}, {L4(b)}, {L4(o)} }},")
    lines.extend(["}};", "} // namespace hsma::golden"])
    
    path = f"{outdir}/poseidon_golden.hpp"
    with open(path, "w") as f: f.write("\n".join(lines) + "\n")
    print(f"[emit] {path}")


def emit_smt_scenario(outdir: str):
    SMT_DEPTH = 64
    IDX_MASK  = (1 << 64) - 1

    rng = random.Random(0x57A7E5)
    p   = CURVES["pallas"]["p"]
    MDS = derive_mds(p, POSEIDON_T)
    RC  = derive_rc(p, POSEIDON_RC_COUNT, "PALLAS")
    iv  = {t: iv_derive(p, t) for t in DOMAIN_TAGS}
    NODE, LEAF, IDENT = iv["IV_STATE_NODE"], iv["IV_STATE_LEAF"], iv["IV_IDENT"]

    E = [poseidon3_ref(p, LEAF, 0, 0, MDS, RC)]
    for _ in range(SMT_DEPTH):
        E.append(poseidon3_ref(p, NODE, E[-1], E[-1], MDS, RC))

    def L(k, v):  return poseidon3_ref(p, LEAF, k, v, MDS, RC)
    def Nn(a, b): return poseidon3_ref(p, NODE, a, b, MDS, RC)

    a0, a1 = rng.randrange(p), rng.randrange(p)
    b0, b1 = rng.randrange(p), rng.randrange(p)
    KA = poseidon3_ref(p, IDENT, a0, a1, MDS, RC)
    KB = poseidon3_ref(p, IDENT, b0, b1, MDS, RC)
    ia, ib = KA & IDX_MASK, KB & IDX_MASK
    while ib == ia:
        b1 = rng.randrange(p)
        KB = poseidon3_ref(p, IDENT, b0, b1, MDS, RC)
        ib = KB & IDX_MASK

    def pack(mag, sgn, nonce, fl):
        assert 0 <= mag < (1 << 120) and sgn in (0, 1) and 0 <= nonce < (1 << 63)
        return mag | (sgn << 120) | (nonce << 121) | (fl << 184)

    A0, B0 = pack(123456789, 0, 5, 0), pack(987654321, 0, 9, 0)
    A1, B1 = pack(123456789 - 1000, 0, 6, 0), pack(987654321 + 1000, 0, 9, 0)

    class Tree:
        def __init__(s): s.d = {}
        def node(s, h, prefix):
            items = [(i, kv) for i, kv in s.d.items() if (i >> h) == prefix]
            if not items:
                return E[h], False
            if h == 0:
                (i, (k, v)), = items
                return L(k, v), True
            hl, ha = s.node(h - 1, prefix << 1)
            hr, hb = s.node(h - 1, (prefix << 1) | 1)
            if not ha and not hb:
                return E[h], False
            return Nn(hl, hr), True
        def root(s): return s.node(SMT_DEPTH, 0)[0]

    tr  = Tree()
    ALLOC_SIMPLE = 2 + SMT_DEPTH

    def update(tree, key, packed_new):
        idx = key & IDX_MASK
        old = tree.d.get(idx)
        if old is not None and old[0] == key and old[1] == packed_new:
            return tree.root(), 0, True
        tree.d[idx] = (key, packed_new)
        return tree.root(), ALLOC_SIMPLE, False

    rootA   = update(tr, KA, A0)[0]
    rootAB  = update(tr, KB, B0)[0]
    rootA1  = update(tr, KA, A1)[0]
    rootTX  = update(tr, KB, B1)[0]
    _, alN, noop = update(tr, KA, A1)
    assert noop and alN == 0

    sibs = []
    for h in range(SMT_DEPTH):
        sib_prefix = (ia >> h) ^ 1
        hh, _pres = tr.node(h, sib_prefix)
        sibs.append(hh)

    fold = L(KA, A1)
    for h in range(SMT_DEPTH):
        bit = (ia >> h) & 1
        fold = Nn(sibs[h], fold) if bit else Nn(fold, sibs[h])
    assert fold == rootTX, "proof fold mismatch"

    L4 = lambda x: "{ " + ", ".join(f"0x{v:016x}ULL" for v in limbs(x)) + " }"
    
    lines = [
        "// GENERATED FILE - smt_golden.hpp",
        "#pragma once",
        "#include <array>",
        "#include <cstdint>",
        "namespace hsma::golden {",
        "struct Sib { std::uint64_t h[4]; };",
        "struct SmtScenario {",
        "  std::uint64_t pkA0[4], pkA1[4], pkB0[4], pkB1[4];",
        "  std::uint64_t keyA[4], keyB[4];",
        "  std::uint64_t packA0[4], packB0[4], packA1[4], packB1[4];",
        "  std::uint64_t rootA[4], rootAB[4], rootA1[4], rootTX[4];",
        "  std::uint64_t E0[4], E1[4], E2[4];",
        "  std::uint64_t allocInsA, allocInsB, allocTxA, allocTxB, allocNoop;",
        "  unsigned char noopIsNoop;",
        "  Sib sibs[64];",
        "  std::uint64_t proofRoot[4];",
        "  unsigned char proofOccupied;",
        "};",
        "inline constexpr SmtScenario SMT_SCENARIO = {",
        f"  {L4(a0)}, {L4(a1)}, {L4(b0)}, {L4(b1)},",
        f"  {L4(KA)}, {L4(KB)},",
        f"  {L4(A0)}, {L4(B0)}, {L4(A1)}, {L4(B1)},",
        f"  {L4(rootA)}, {L4(rootAB)}, {L4(rootA1)}, {L4(rootTX)},",
        f"  {L4(E[0])}, {L4(E[1])}, {L4(E[2])},",
        f"  {ALLOC_SIMPLE}ULL, {ALLOC_SIMPLE}ULL, {ALLOC_SIMPLE}ULL, {ALLOC_SIMPLE}ULL, 0ULL,",
        "  1,",
        "  {",
        ",\n".join("    { " + L4(h) + " }" for h in sibs),
        "  },",
        f"  {L4(rootTX)},",
        "  1",
        "};",
        "} // namespace hsma::golden"
    ]
    
    path_out = f"{outdir}/smt_golden.hpp"
    with open(path_out, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[emit] {path_out}  (roots A/AB/A1/TX anchored, proof fold verified)")

# ═══════════════════════════════════════════════════════════════════════════
#  STEP 6 APPEND — MSSC reference automaton + golden trace (DEC-136..139, E-7)
# ═══════════════════════════════════════════════════════════════════════════
import bisect

CONS_NV, CONS_NHON      = 48, 38
CONS_W_HON, CONS_W_ADV  = 100, 10
CONS_EPOCH              = 7
K_BASE, K_ESC, K_ESC_AT = 20, 40, 1000
BETA, STALL_LIM         = 150, 50
PHI_BP, ALPHA_BP        = 5000, 7500
GRACE_MS                = 400
TAG_SEED   = b"HSM_PEERSEED_v1"
TAG_BEACON = b"HSM_SIM_BEACON_v1"

K_FLOOR, K_NOQ, K_SWITCH, K_CONF = 0, 1, 2, 3
F_FINAL, F_SUSP                  = 4, 8

def _u64(x): return x.to_bytes(8, "little")
def _dw(seed, ctr): return int.from_bytes(
    hashlib.sha256(seed + _u64(ctr)).digest()[:8], "little")

def _cons_static():
    vid  = [hashlib.sha256(b"HSMA-VAL" + _u64(i)).digest() for i in range(CONS_NV)]
    wt   = [CONS_W_HON if i < CONS_NHON else CONS_W_ADV for i in range(CONS_NV)]
    T    = sum(wt)
    wr   = hashlib.sha256(b"".join(vid[i] + _u64(wt[i])
                                   for i in range(CONS_NV))).digest()
    txh  = hashlib.sha256(b"HSMA-TX"  + _u64(1)).digest()
    txa  = hashlib.sha256(b"HSMA-TX"  + _u64(2)).digest()
    cid  = [hashlib.sha256(b"HSMA-CID" + _u64(11 + i)).digest() for i in range(3)]
    b1   = hashlib.sha256(TAG_BEACON + _u64(CONS_EPOCH)     + bytes(32)).digest()
    b2   = hashlib.sha256(TAG_BEACON + _u64(CONS_EPOCH + 1) + b1).digest()
    return vid, wt, T, wr, txh, txa, cid, b1, b2

class RefAuto:
    """Python mirror of hsma::consensus::Automaton — byte-exact semantics."""
    def __init__(s):
        s.vid, s.wt, s.T, s.wroot, s.txh, s.txa, s.cid, s.b1, s.b2 = _cons_static()
        s.cum, t = [], 0
        for w in s.wt: t += w; s.cum.append(t)
        s.self_row = 0                                  # observer = validator 0
    def draw(s, seed, k):
        seen, out, ctr = set(), [], 0
        while len(out) < k:
            pick = _dw(seed, ctr) % s.T; ctr += 1
            i = bisect.bisect_right(s.cum, pick)
            if i == s.self_row or i in seen: continue
            seen.add(i); out.append(i)
        return out
    def tick(s, st, cid, beacon, pool):
        # st = dict(rounds, pref, conf, stall, state)
        if st["state"] != "A": return None
        st["rounds"] += 1
        rnd = st["rounds"]
        k = K_ESC if rnd >= K_ESC_AT else K_BASE
        seed = TAG_SEED + _u64(CONS_EPOCH) + s.wroot + beacon + cid \
             + _u64(rnd) + s.vid[s.self_row]
        S, tal = 0, {}
        for i in s.draw(seed, k):
            v = pool.get(i)
            if v is None: continue
            if v["epoch"] != CONS_EPOCH or v["wroot"] != s.wroot: continue
            if v["cid"] != cid          or v["round"] != rnd:        continue
            S += s.wt[i]
            tal[v["pref"]] = tal.get(v["pref"], 0) + s.wt[i]
        fl_n, fl_d = PHI_BP * k * s.T, 10000 * CONS_NV      # S*fl_d >= fl_n
        row_kind = None
        if S * 10000 * CONS_NV < fl_n:
            st["conf"] = 0; st["stall"] += 1; row_kind = K_FLOOR
        else:
            best = sorted(tal.items(), key=lambda kv: (-kv[1], kv[0]))[0]
            if best[1] * 10000 >= ALPHA_BP * S:
                st["stall"] = 0
                if best[0] == st["pref"]:
                    st["conf"] += 1; row_kind = K_CONF
                else:
                    st["pref"] = best[0]; st["conf"] = 1; row_kind = K_SWITCH
            else:
                st["conf"] = 0; st["stall"] += 1; row_kind = K_NOQ
        fin = st["conf"] >= BETA
        sus = st["stall"] >= STALL_LIM
        if fin: st["state"] = "F"
        elif sus: st["state"] = "S"
        return (row_kind | (F_FINAL if fin else 0) | (F_SUSP if sus else 0),
                st["conf"], st["stall"], S, k)
    @staticmethod
    def breaker(frozen, beacon):
        hs = [(hashlib.sha256(beacon + f).digest(), f) for f in frozen]
        hs.sort(key=lambda p: p[0])                          # byte-lex asc
        return hs[-1][1]                                     # argmax
    @staticmethod
    def stagger(beacon, cid):
        return int.from_bytes(hashlib.sha256(beacon + cid).digest()[:8],
                              "little") % GRACE_MS

def emit_consensus_scenario(outdir: str):
    """Realized-trace goldens (DEC-139) with CA-120 brace law enforced."""
    au = RefAuto()
    def H(b): return "".join(f"0x{x:02x}," for x in b).rstrip(",")

    def mkpool(pairs):
        return {i: {"epoch": CONS_EPOCH, "wroot": au.wroot, "cid": None,
                    "round": 0, "pref": p} for i, p in pairs}

    st1 = {"rounds": 0, "pref": au.txh, "conf": 0, "stall": 0, "state": "A"}
    pool1 = mkpool([(i, au.txh if i < CONS_NHON else au.txa)
                    for i in range(CONS_NV)])
    tr1, fin_r = [], None
    for r in range(1, 401):
        for v in pool1.values(): v["cid"], v["round"] = au.cid[0], r
        row = au.tick(st1, au.cid[0], au.b1, pool1)
        tr1.append(row)
        if st1["state"] == "F": fin_r = r; break
    assert fin_r and st1["pref"] == au.txh

    st2 = {"rounds": 0, "pref": au.txh, "conf": 0, "stall": 0, "state": "A"}
    pool2 = mkpool([(i, au.txa) for i in range(CONS_NHON, CONS_NV)])
    tr2, sus_r = [], None
    for r in range(1, 151):
        for v in pool2.values(): v["cid"], v["round"] = au.cid[1], r
        row = au.tick(st2, au.cid[1], au.b1, pool2)
        tr2.append(row)
        if st2["state"] == "S": sus_r = r; break
    assert sus_r and st2["stall"] >= STALL_LIM

    winner = RefAuto.breaker([au.txh, au.txa], au.b2)
    delay  = RefAuto.stagger(au.b2, au.cid[1])

    st3 = {"rounds": 0, "pref": au.txh, "conf": 0, "stall": 0, "state": "A"}
    want = [1, 2, 999, 1000, 1001, 1200]
    tr3 = []
    for r in range(1, 1201):
        pref = au.txh if r % 2 == 1 else au.txa
        pool3 = mkpool([(i, pref) for i in range(CONS_NHON)])
        for v in pool3.values(): v["cid"], v["round"] = au.cid[2], r
        row = au.tick(st3, au.cid[2], au.b1, pool3)
        if r in want: tr3.append((r, row))
    assert st3["state"] == "A"

    N = str(CONS_NV)
    cid_rows = ",".join("{" + H(c) + "}" for c in au.cid)          # '{a},{b},{c}'
    out = ["// GENERATED FILE - consensus_golden.hpp (realized trace)",
           "#pragma once", "#include <array>", "#include <cstdint>",
           "namespace hsma::golden {",
           "struct TickRow { std::uint8_t kind; std::uint32_t conf, stall;",
           "                 std::uint64_t s, k; };",
           "inline constexpr std::uint64_t G_W[" + N + "]{"
               + ",".join(str(w) for w in au.wt) + "};",
           "inline constexpr std::uint64_t G_T=" + str(au.T)
               + ", G_EPOCH=" + str(CONS_EPOCH) + ";",
           "inline constexpr std::uint8_t G_VID[" + N + "][32]{"
               + ",".join("{" + H(v) + "}" for v in au.vid) + "};",
           "inline constexpr std::uint8_t G_WROOT[32]{" + H(au.wroot) + "};",
           "inline constexpr std::uint8_t G_TXH[32]{" + H(au.txh) + "};",
           "inline constexpr std::uint8_t G_TXA[32]{" + H(au.txa) + "};",
           "inline constexpr std::uint8_t G_CID[3][32]{" + cid_rows + "};",
           "inline constexpr std::uint8_t G_B1[32]{" + H(au.b1) + "};",
           "inline constexpr std::uint8_t G_B2[32]{" + H(au.b2) + "};",
           "inline constexpr TickRow G_C1[" + str(len(tr1)) + "]{"]
    out += ["{%d,%d,%d,%d,%d}," % t for t in tr1]
    out += ["};",
            "inline constexpr std::uint32_t G_C1_FIN=" + str(fin_r) + ";",
            "inline constexpr TickRow G_C2[" + str(len(tr2)) + "]{"]
    out += ["{%d,%d,%d,%d,%d}," % t for t in tr2]
    out += ["};",
            "inline constexpr std::uint32_t G_C2_SUS=" + str(sus_r) + ";",
            "inline constexpr std::uint32_t G_C3_AT[6]{"
                + ",".join(str(r) for r, _ in tr3) + "};",
            "inline constexpr TickRow G_C3[6]{"]
    out += ["{%d,%d,%d,%d,%d}," % t for _, t in tr3]
    out += ["};",
            "inline constexpr std::uint8_t G_WINNER[32]{" + H(winner) + "};",
            "inline constexpr std::uint64_t G_DELAY=" + str(delay) + "ull;",
            "} // namespace hsma::golden"]

    text = "\n".join(out) + "\n"

    # ── BRACE LAW v3 (DEC-146): grammar-aware, compiler-aligned ──
    import re as _re
    if "{{{" in text:
        sys.exit("BRACE LAW: triple opener present")
    for _m in _re.finditer(r"\w+\[\d+\](?:\[\d+\])?\{", text):
        # 1-D array ([N]{) followed by '{'  -> illegal doubling.
        # 2-D array ([N][M]{) followed by '{' -> mandatory nesting syntax.
        if _m.group(0).count("[") == 1 and text[_m.end():_m.end()+1] == "{":
            _ln = text[:_m.start()].count("\n") + 1
            sys.exit(f"BRACE LAW: 1-D array doubled opener at line {_ln}")
    if text.count("{") != text.count("}"):
        sys.exit("BRACE LAW: unbalanced braces")

    path = f"{outdir}/consensus_golden.hpp"
    with open(path, "w") as f: f.write(text)
    print(f"[emit] {path}  (C1 fin@{fin_r}, C2 sus@{sus_r}, "
          f"winner={'H' if winner==au.txh else 'A'}, delay={delay})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    for name, spec in CURVES.items():
        v = validate(name, spec)
        emit_header(name, v, a.out)
    emit_field_vectors(a.out)
    emit_rnte_vectors(a.out)
    emit_poseidon(a.out)
    emit_poseidon_goldens(a.out)
    emit_smt_scenario(a.out)
    emit_consensus_scenario(a.out)
    print("[done] all constants derived, validated, emitted.")


if __name__ == "__main__":
    main()



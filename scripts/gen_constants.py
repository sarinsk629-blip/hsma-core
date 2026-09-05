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



# ============ STEP 7 APPEND - BLS12-377 scalar field F_r + threshold goldens (DEC-181..184) ============
import hashlib as _h7, re as _re7, os as _os7

def _step7_fatal(msg):
    print("[step7] FATAL: " + msg); raise SystemExit(1)

_DOCUMENTED_R = 8444461749428370424248824938781546531375899335154063827935233455917409239041  # CA-6/DEC-045 record

def _step7_prime(n):
    if n < 2: return False
    for p in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n % p == 0: return n == p
    d = n - 1; s = 0
    while d % 2 == 0: d //= 2; s += 1
    bases = [2,3,5,7,11,13,17,19,23,29,31,37] + \
        [int.from_bytes(_h7.sha256(b"HSM_MR_v1" + bytes([i])).digest()[:16], "big") % (n - 3) + 2 for i in range(40)]
    for a in set(bases):
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        ok = False
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1: ok = True; break
        if not ok: return False
    return True

def _step7_draw(n_, limit, salt):
    out = []; i = 0
    while len(out) < n_:
        v = int.from_bytes(_h7.sha256(salt + i.to_bytes(8, "big")).digest(), "big")
        i += 1
        if 0 < v < limit: out.append(v)
    return out

_S7_M64 = (1 << 64) - 1
def _s7_row(v):
    return "{0x%016xull, 0x%016xull, 0x%016xull, 0x%016xull}" % \
        (v & _S7_M64, (v >> 64) & _S7_M64, (v >> 128) & _S7_M64, (v >> 192) & _S7_M64)
def _s7_rows(vals):
    return ",\n    ".join(_s7_row(v) for v in vals)

def _s7_pe(c, j, r):
    acc = 0
    for k in reversed(range(len(c))): acc = (acc * j + c[k]) % r
    return acc

def _step7():
    src = None
    for c in ("tools/bls_derive.cpp", "../tools/bls_derive.cpp"):
        if _os7.path.isfile(c): src = open(c, encoding="utf-8", errors="ignore").read(); break
    if src is None: _step7_fatal("tools/bls_derive.cpp not found (CWD=%s)" % _os7.getcwd())
    r = _DOCUMENTED_R
    toks = [int(t, 16) for t in _re7.findall(r'0x[0-9a-fA-F]+', src)]
    toks += [int(t) for t in _re7.findall(r'(?<![\w.])\d{16,22}(?![\w.])', src)]
    prov = None
    for v in sorted(set(toks)):
        if v == r:
            prov = 'direct r literal 0x%x in kernel source' % v; break
        if 1 < v < (1 << 70):
            if pow(v, 4) - v * v + 1 == r:
                prov = 'kernel parameter x = 0x%x (identity x^4 - x^2 + 1 == r)' % v; break
            if pow(v, 8) - pow(v, 4) + 1 == r:
                prov = 'kernel parameter x = 0x%x (identity x^8 - x^4 + 1 == r)' % v; break
    if prov is None:
        print('[step7] FATAL: no literal in bls_derive.cpp satisfies r directly or via x^4-x^2+1 - dump:')
        for i, l in enumerate(src.splitlines(), 1):
            if _re7.search(r'0x[0-9a-fA-F]{12,}', l) or 'g_r' in l:
                print('  L%d: %s' % (i, l.strip()[:170]))
        for i, l in enumerate(src.splitlines(), 1):
            if 150 <= i <= 205:
                print('  R%d: %s' % (i, l.rstrip()[:170]))
        raise SystemExit(1)
    print('[step7][prov] %s' % prov)
    if not _step7_prime(r): _step7_fatal("r failed MR-52 primality")
    one = pow(2, 256, r); r2 = pow(2, 512, r); m2 = r - 2
    inv0 = (-pow(r, -1, 1 << 64)) % (1 << 64)
    assert (inv0 * r) % (1 << 64) == (1 << 64) - 1
    d_ = r - 1; s_ = 0
    while d_ % 2 == 0: d_ //= 2; s_ += 1

    C = 64; NP = 5; T = 3
    A = _step7_draw(C, r, b"HSM_G7_DRBG_v1A"); B = _step7_draw(C, r, b"HSM_G7_DRBG_v1B")
    ADD = [(a + b) % r for a, b in zip(A, B)]
    SUB = [(a - b) % r for a, b in zip(A, B)]
    MUL = [a * b % r for a, b in zip(A, B)]
    INV = [pow(a, -1, r) for a in A]
    co = _step7_draw(NP * T, r, b"HSM_G7_DRBG_v1P")
    polys = [co[i * T:(i + 1) * T] for i in range(NP)]
    ids = list(range(1, NP + 1))
    share = [[_s7_pe(polys[i], j, r) for j in ids] for i in range(NP)]
    S = [sum(share[i][j - 1] for i in range(NP)) % r for j in ids]
    subset = [2, 3, 5]
    lam = []
    for i in subset:
        l = 1
        for j in subset:
            if j == i: continue
            l = l * (-j) % r * pow(i - j, -1, r) % r
        lam.append(l)
    secret = sum(polys[i][0] for i in range(NP)) % r
    rec = sum(l * S[i - 1] for l, i in zip(lam, subset)) % r
    assert rec == secret, "Lagrange self-check failed"
    rec_t = (lam[0] * S[1] + lam[1] * ((S[2] + 1) % r) + lam[2] * S[4]) % r
    assert rec_t != secret, "tamper divergence failed - redraw salt"

    cdirs = set()
    for root, dirs, files in _os7.walk("."):
        if ".git" in root.split(_os7.sep): continue
        if "pallas_params_gen.hpp" in files: cdirs.add(root)
    if len(cdirs) != 1: _step7_fatal("ambiguous generated dirs: %r" % sorted(cdirs))
    outdir = cdirs.pop()

    hp = ("// GENERATED by scripts/gen_constants.py - STEP 7 (DEC-182). DO NOT EDIT.\n"
          "// Authority: modulus extracted from tools/bls_derive.cpp literals, cross-checked\n"
          "// against the documented BLS12-377 r (CA-6/DEC-045 record), MR-52 primality.\n"
          "#pragma once\n#include <cstdint>\nnamespace hsma::bls {\n"
          "inline constexpr std::uint64_t R_MOD[4] = %s;\n"
          "inline constexpr std::uint64_t R_ONE[4] = %s;  // 2^256 mod r - Montgomery rep of 1\n"
          "inline constexpr std::uint64_t R_R2[4]  = %s;  // 2^512 mod r - plain->Montgomery\n"
          "inline constexpr std::uint64_t R_M2[4]  = %s;  // r - 2 - Fermat exponent\n"
          "inline constexpr std::uint64_t R_INV0   = 0x%016xull;  // -r^-1 mod 2^64\n"
          "inline constexpr unsigned     R_BITS    = %du;\n}\n"
          ) % (_s7_row(r), _s7_row(one), _s7_row(r2), _s7_row(m2), inv0, r.bit_length())

    hg = ("// GENERATED by scripts/gen_constants.py - STEP 7 (DEC-183). DO NOT EDIT.\n"
          "// Ground truth: Python big-int. DRBG: SHA-256 counter (RC-derivation style, DEC-107).\n"
          "#pragma once\n#include <cstdint>\nnamespace hsma::golden {\n"
          "inline constexpr unsigned G7_COUNT = %du;\n" % C)
    for nm, vv in (("G7_A", A), ("G7_B", B), ("G7_ADD", ADD), ("G7_SUB", SUB),
                   ("G7_MUL", MUL), ("G7_INV", INV)):
        hg += "inline constexpr std::uint64_t %s[G7_COUNT][4] = {\n    %s\n};\n" % (nm, _s7_rows(vv))
    hg += "inline constexpr std::uint64_t G7_ONE[4] = %s;\n" % _s7_row(1)
    hg += "inline constexpr std::uint64_t G7_Rm1[4] = %s;\n" % _s7_row(r - 1)
    hg += "inline constexpr std::uint64_t G7_POLY[5][3][4] = {\n"
    hg += ",\n    ".join("{\n        " + ",\n        ".join(_s7_row(c) for c in p) + "\n    }" for p in polys)
    hg += "\n};\n"
    hg += "inline constexpr std::uint64_t G7_SHARE[5][5][4] = {\n"
    hg += ",\n    ".join("{\n        " + ",\n        ".join(_s7_row(share[i][j]) for j in range(5)) + "\n    }" for i in range(5))
    hg += "\n};\n"
    hg += "inline constexpr std::uint64_t G7_IDS[3] = { 2u, 3u, 5u };\n"
    hg += "inline constexpr std::uint64_t G7_LAM[3][4] = {\n    %s\n};\n" % ",\n    ".join(_s7_row(l) for l in lam)
    hg += "inline constexpr std::uint64_t G7_SECRET[4] = %s;\n}\n" % _s7_row(secret)

    hp = hp.replace("MR-52 primality.", "MR-52 primality. Provenance: " + prov + ".")
    open(_os7.path.join(outdir, "bls_params_gen.hpp"), "w").write(hp)
    open(_os7.path.join(outdir, "threshold_golden.hpp"), "w").write(hg)
    print("[validate] bls-r: matches documented r, MR-52 prime, bits=%d, 2-adicity(r-1)=%d, inv0=OK"
          % (r.bit_length(), s_))
    print("[step7][emit] bls_params_gen.hpp")
    print("[step7][emit] threshold_golden.hpp (%d pairs, DKG n=5/t=3, tamper divergence asserted)" % C)

_step7()

# ═══ STEP 8 APPEND — E(F_q) promotion: constants + affine-EC goldens (DEC-185..188) ═══
import hashlib as _h8, os as _os8

_S8_M64 = (1 << 64) - 1
_S8_X = 0x8508c00000000001   # matches SEED_X; identity-anchored (CA-R32 doctrine)

def _step8_fatal(msg):
    print("[step8] FATAL: " + msg); raise SystemExit(1)

def _s8_row6(v):
    return "{0x%016xull, 0x%016xull, 0x%016xull, 0x%016xull, 0x%016xull, 0x%016xull}" % (
        v & _S8_M64, (v >> 64) & _S8_M64, (v >> 128) & _S8_M64,
        (v >> 192) & _S8_M64, (v >> 256) & _S8_M64, (v >> 320) & _S8_M64)

def _s8_rows6(vals):
    return ",\n    ".join(_s8_row6(v) for v in vals)

def _s8_pair_rows(Ps):
    return ",\n    ".join("{ " + _s8_row6(p[0]) + ", " + _s8_row6(p[1]) + " }" for p in Ps)

def _s8_draw(n_, limit, salt):   # 256-bit draws: <q(377b) always; <r(253b) ~1/8
    out = []; i = 0
    while len(out) < n_:
        v = int.from_bytes(_h8.sha256(salt + i.to_bytes(8, "big")).digest(), "big")
        i += 1
        if 0 < v < limit: out.append(v)
    return out

def _s8_tonelli(a, q):
    if a % q == 0: return 0
    e = 0; s = q - 1
    while s % 2 == 0: s //= 2; e += 1
    z = 2
    while pow(z, (q - 1) // 2, q) != q - 1: z += 1
    M, c, t, R = e, pow(z, s, q), pow(a, s, q), pow(a, (s + 1) // 2, q)
    while t != 1:
        i, t2 = 0, t
        while t2 != 1: t2 = t2 * t2 % q; i += 1
        b = pow(c, 1 << (M - i - 1), q)
        M, c, t = i, b * b % q, t * b * b % q
        R = R * b % q            # UNCONDITIONAL (kernel invariant R^2 = t*a)
    return R

def _s8_add(P, Q, q):           # affine E: y^2 = x^3 + 1; None = infinity
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % q == 0: return None
        lam = (3 * x1 * x1) * pow(2 * y1, -1, q) % q
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, q) % q
    x3 = (lam * lam - x1 - x2) % q
    return (x3, (lam * (x1 - x3) - y1) % q)

def _s8_mul(P, k, q):
    R, A = None, P
    while k:
        if k & 1: R = _s8_add(R, A, q)
        A = _s8_add(A, A, q)
        k >>= 1
    return R

def _s8_pt_from_x(x, q):
    rhs = (pow(x, 3, q) + 1) % q
    if pow(rhs, (q - 1) // 2, q) != 1: return None
    return (x, _s8_tonelli(rhs, q))

def _step8_params():
    x = _S8_X
    r = x**4 - x**2 + 1
    if r != _DOCUMENTED_R: _step8_fatal("r != step7 documented r")
    if (x - 1)**2 % 3 != 0: _step8_fatal("(x-1)^2 mod 3 != 0")
    h1 = (x - 1)**2 // 3
    q = h1 * r + x
    if q % (1 << 64) != x: _step8_fatal("ancestry: q low limb != x")
    if q.bit_length() != 377 or r.bit_length() != 253: _step8_fatal("widths q/r")
    if not _step7_prime(q): _step8_fatal("q failed MR")
    if not _step7_prime(r): _step8_fatal("r failed MR")
    e = 0; s = q - 1
    while s % 2 == 0: s //= 2; e += 1
    gy = _s8_tonelli(2, q)
    if gy * gy % q != 2: _step8_fatal("gy^2 != 2")
    if gy & 1: gy = q - gy                 # kernel law: even low limb
    if gy & 1: _step8_fatal("gy parity")
    GEN = _s8_mul((1, gy), h1, q)          # cofactor-cleared generator
    if GEN is None: _step8_fatal("GEN vanished")
    gx, gyy = GEN
    if (gyy * gyy - (gx * gx * gx + 1)) % q != 0: _step8_fatal("GEN off curve")
    if _s8_mul(GEN, r, q) is not None: _step8_fatal("GEN not in r-subgroup")
    return dict(x=x, r=r, h1=h1, q=q, e=e, sodd=s, gy=gy,
                gen=(gx, gyy), ne=h1 * r,
                one=pow(2, 384, q), r2=pow(2, 768, q), m2=q - 2,
                halfq=(q - 1) // 2, n0=(-pow(q, -1, 1 << 64)) % (1 << 64))

def _step8():
    P8 = _step8_params()
    print("[t8] params OK")
    q, r, e, sodd = P8["q"], P8["r"], P8["e"], P8["sodd"]
    FQ = 48
    A = _s8_draw(FQ, q, b"HSM_G8_FQ_A"); B = _s8_draw(FQ, q, b"HSM_G8_FQ_B")
    ADD = [(a + b) % q for a, b in zip(A, B)]
    SUB = [(a - b) % q for a, b in zip(A, B)]
    MUL = [a * b % q for a, b in zip(A, B)]
    pts = []
    _att = 0
    while len(pts) < 4:
        cand = _s8_draw(1, q, b"HSM_G8_PX" + _att.to_bytes(8, "big"))[0]
        _att += 1
        if _att > 1000: _step8_fatal("pts starved")
        P = _s8_pt_from_x(cand, q)
        if P is not None: pts.append(P)
    ADDT = []
    for i in range(4):
        Pp, Qq = pts[i], pts[(i + 1) % 4]
        Rr = _s8_add(Pp, Qq, q)
        if Rr is None: _step8_fatal("add triple infinity - redraw salt")
        ADDT.append((Pp, Qq, Rr))
    DBLT = []
    for Pp in pts:
        D = _s8_add(Pp, Pp, q)
        if D is None: _step8_fatal("dbl infinity")
        DBLT.append((Pp, D))
    ks = _s8_draw(4, r, b"HSM_G8_K")
    print("[t8] ks drawn (r-limit draws healthy)")
    MULt = []
    for i in range(4):
        Rr = _s8_mul(pts[i], ks[i], q)
        if Rr is None: _step8_fatal("mul triple infinity - redraw salt")
        MULt.append((ks[i], pts[i], Rr))
    TS = []
    _att = 0
    while len(TS) < 8:
        v = _s8_draw(1, q, b"HSM_G8_TS" + _att.to_bytes(8, "big"))[0]
        _att += 1
        if _att > 1000: _step8_fatal("TS starved")
        if pow(v, (q - 1) // 2, q) != 1: continue
        TS.append((v, _s8_tonelli(v, q)))
    for v, w in TS:
        if w * w % q != v: _step8_fatal("TS w^2 != v")
    cdirs = set()
    for root, dirs, files in _os8.walk("."):
        if ".git" in root.split(_os8.sep): continue
        if "pallas_params_gen.hpp" in files: cdirs.add(root)
    if len(cdirs) != 1: _step8_fatal("ambiguous generated dirs")
    outdir = cdirs.pop()
    hp = ("// GENERATED by scripts/gen_constants.py - STEP 8 (DEC-186). DO NOT EDIT.\n"
          "// Provenance: q = h1*r + x, h1 = (x-1)^2/3, r = x^4-x^2+1, x = 0x8508c00000000001\n"
          "// (identity-anchored vs SEED_X, CA-R32). Validated: q,r MR-52; widths 377/253;\n"
          "// ancestry; gy^2=2; GEN on-curve; [r]GEN = inf (Python affine oracle).\n"
          "#pragma once\n#include <cstdint>\nnamespace hsma::blsq {\n")
    hp += "inline constexpr std::uint64_t Q_MOD[6] = %s;\n" % _s8_row6(q)
    hp += "inline constexpr std::uint64_t Q_R1[6] = %s;  // 2^384 mod q\n" % _s8_row6(P8["one"])
    hp += "inline constexpr std::uint64_t Q_R2[6] = %s;  // 2^768 mod q\n" % _s8_row6(P8["r2"])
    hp += "inline constexpr std::uint64_t Q_M2[6] = %s;  // q - 2\n" % _s8_row6(P8["m2"])
    hp += "inline constexpr std::uint64_t Q_HALFQ[6] = %s;  // (q-1)/2\n" % _s8_row6(P8["halfq"])
    hp += "inline constexpr std::uint64_t Q_RMOD[6] = %s;  // r (subgroup exponent)\n" % _s8_row6(r)
    hp += "inline constexpr std::uint64_t Q_H1[6] = %s;  // cofactor\n" % _s8_row6(P8["h1"])
    hp += "inline constexpr std::uint64_t Q_SODD[6] = %s;  // odd part of q-1\n" % _s8_row6(sodd)
    hp += "inline constexpr std::uint64_t Q_NE[6] = %s;  // h1*r = #E\n" % _s8_row6(P8["ne"])
    hp += "inline constexpr std::uint64_t Q_GEN_X[6] = %s;  // generator x, affine canonical\n" % _s8_row6(P8["gen"][0])
    hp += "inline constexpr std::uint64_t Q_GEN_Y[6] = %s;  // generator y, affine canonical\n" % _s8_row6(P8["gen"][1])
    hp += "inline constexpr std::uint64_t Q_N0 = 0x%016xull;  // -q^-1 mod 2^64\n" % P8["n0"]
    hp += "inline constexpr unsigned Q_E = %uu;  // 2-adicity of q-1\n}\n" % e
    hg = ("// GENERATED by scripts/gen_constants.py - STEP 8 (DEC-187). DO NOT EDIT.\n"
          "// Oracle: Python plain-int AFFINE EC (independent of C++ Jacobian/Montgomery).\n"
          "#pragma once\n#include <cstdint>\nnamespace hsma::golden {\n")
    hg += "inline constexpr unsigned G8_FQ = %uu;\n" % FQ
    for nm, vv in (("G8_A", A), ("G8_B", B), ("G8_ADD", ADD), ("G8_SUB", SUB), ("G8_MUL", MUL)):
        hg += "inline constexpr std::uint64_t %s[G8_FQ][6] = {\n    %s\n};\n" % (nm, _s8_rows6(vv))
    hg += "inline constexpr std::uint64_t G8_ADD_P[4][2][6] = {\n    %s\n};\n" % _s8_pair_rows([t[0] for t in ADDT])
    hg += "inline constexpr std::uint64_t G8_ADD_Q[4][2][6] = {\n    %s\n};\n" % _s8_pair_rows([t[1] for t in ADDT])
    hg += "inline constexpr std::uint64_t G8_ADD_R[4][2][6] = {\n    %s\n};\n" % _s8_pair_rows([t[2] for t in ADDT])
    hg += "inline constexpr std::uint64_t G8_DBL_P[4][2][6] = {\n    %s\n};\n" % _s8_pair_rows([t[0] for t in DBLT])
    hg += "inline constexpr std::uint64_t G8_DBL_R[4][2][6] = {\n    %s\n};\n" % _s8_pair_rows([t[1] for t in DBLT])
    hg += "inline constexpr std::uint64_t G8_MUL_K[4][6] = {\n    %s\n};\n" % _s8_rows6(ks)
    hg += "inline constexpr std::uint64_t G8_MUL_P[4][2][6] = {\n    %s\n};\n" % _s8_pair_rows([t[1] for t in MULt])
    hg += "inline constexpr std::uint64_t G8_MUL_R[4][2][6] = {\n    %s\n};\n" % _s8_pair_rows([t[2] for t in MULt])
    hg += "inline constexpr std::uint64_t G8_TS_X[8][6] = {\n    %s\n};\n" % _s8_rows6([t[0] for t in TS])
    hg += "inline constexpr std::uint64_t G8_TS_W[8][6] = {\n    %s\n};\n}\n" % _s8_rows6([t[1] for t in TS])
    open(_os8.path.join(outdir, "bls_q_params_gen.hpp"), "w").write(hp)
    print("[t8] bls_q_params_gen.hpp written")
    open(_os8.path.join(outdir, "bls_curve_golden.hpp"), "w").write(hg)
    print("[t8] bls_curve_golden.hpp written")
    print("[validate] bls-q: MR-52 prime, 377 bits, ancestry OK, 2adic(q-1)=%d" % e)
    print("[step8][emit] bls_q_params_gen.hpp (q, mont consts, GEN)")
    print("[step8][emit] bls_curve_golden.hpp (%d fq pairs, 4+4+4 triples, 8 tonelli)" % FQ)

_step8()

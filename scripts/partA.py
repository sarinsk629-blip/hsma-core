# ═══════════════════════════════════════════════════════════════════════════
#  STEP 3 APPEND — Poseidon-3 instance, domain registry, goldens (DEC-107..109)
# ═══════════════════════════════════════════════════════════════════════════
import hashlib as hl
import re as _re

POSEIDON_T, POSEIDON_RF, POSEIDON_RP, POSEIDON_ALPHA = 3, 8, 56, 5
POSEIDON_RC_COUNT = (POSEIDON_RF // 2) * POSEIDON_T * 2 + POSEIDON_RP      # = 80
POSEIDON_SCHEDULE = "HSMA-P3-v1"     # frozen round convention id (DEC-107)

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

def _drbg(seed: bytes, nbytes: int) -> bytes:
    out, ctr = bytearray(), 0
    while len(out) < nbytes:
        out += hl.sha256(seed + ctr.to_bytes(8, "little")).digest()
        ctr += 1
    return bytes(out[:nbytes])

def derive_rc(p: int, n: int, label: str) -> list[int]:
    """Round constants: SHA-256 counter DRBG, 320-bit draws, rejection to [0,p)."""
    seed = b"HSM_POSEIDON_RC_v1|" + POSEIDON_SCHEDULE.encode() + b"|" + label.encode()
    stream, out, off = _drbg(seed, n * 48 + 64), [], 0
    while len(out) < n:
        v = int.from_bytes(stream[off:off + 40], "big")     # BE draw — frozen
        off += 40
        if v < p:
            out.append(v)
    return out

def _det3(M, p):
    return (M[0][0]*(M[1][1]*M[2][2]-M[1][2]*M[2][1])
          - M[0][1]*(M[1][0]*M[2][2]-M[1][2]*M[2][0])
          + M[0][2]*(M[1][0]*M[2][1]-M[1][1]*M[2][0])) % p

def derive_mds(p: int, t: int) -> list[list[int]]:
    """Cauchy construction M[i][j] = 1/(x_i+y_j); positivity ⇒ denominators safe."""
    xs, ys = list(range(1, t + 1)), list(range(t + 1, 2 * t + 1))
    M = [[pow(xs[i] + ys[j], -1, p) for j in range(t)] for i in range(t)]
    # ── MACHINE-CHECKED MDS PROOF: every square minor nonsingular (exact test,
    #    stronger and cheaper than sampling) ──
    for i in range(t):
        for j in range(t):
            assert M[i][j] % p != 0, "MDS entry zero"
    for i1 in range(t):
        for i2 in range(i1 + 1, t):
            for j1 in range(t):
                for j2 in range(j1 + 1, t):
                    d = (M[i1][j1]*M[i2][j2] - M[i1][j2]*M[i2][j1]) % p
                    assert d != 0, "2x2 minor singular — not MDS"
    assert _det3(M, p) != 0, "3x3 minor singular — not MDS"
    return M

def iv_derive(p: int, tag: str) -> int:
    """IV = rejection-sample(SHA256('HSM_IV_v1|'‖tag‖u64le(nonce))), LE read."""
    nonce = 0
    while True:
        h = hl.sha256(b"HSM_IV_v1|" + tag.encode() + nonce.to_bytes(8, "little")).digest()
        v = int.from_bytes(h, "little")                      # LE read — frozen
        if v < p:
            return v
        nonce += 1

def poseidon3_ref(p: int, iv: int, l: int, r: int, MDS, RC) -> int:
    """Reference permutation — plain ints mod p (NO Montgomery). Convention:
    round = { ark ; sbox(all|first) ; mix }, RC order [pre-full|partial|post-full]."""
    sbox = lambda x: pow(x, POSEIDON_ALPHA, p)
    def mix(s):
        return [sum(MDS[i][j] * s[j] for j in range(POSEIDON_T)) % p
                for i in range(POSEIDON_T)]
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
    assert k == len(RC), "round-constant consumption drift"
    return s[0]

def sponge_ref(p, iv, elems, MDS, RC) -> int:
    """Reference sponge: absorb adds into rate slots (permute on fill);
    finalize absorbs count then ONE, permutes, squeezes s0."""
    s, idx, n = [0, 0, iv], 0, 0
    def permute():
        nonlocal s
        s = [poseidon3_ref.__wrapped__] if False else None   # placeholder, replaced below
    # (direct inline to avoid closure gymnastics)
    def _perm(s):
        return None
    st = {"s": s, "idx": 0}
    def perm():
        st["s"] = _perm_state(p, st["s"], MDS, RC)
    def absorb(x):
        st["s"][st["idx"]] = (st["s"][st["idx"]] + x) % p
        st["idx"] += 1
        if st["idx"] == 2:
            perm(); st["idx"] = 0
        return None
    # local copy of the permutation operating on a 3-vector:
    def _perm_state(p, s, MDS, RC):
        sbox = lambda x: pow(x, POSEIDON_ALPHA, p)
        def mix(s):
            return [sum(MDS[i][j] * s[j] for j in range(3)) % p for i in range(3)]
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
    def perm():
        st["s"] = _perm_state(p, st["s"], MDS, RC)
    def absorb(x):
        st["s"][st["idx"]] = (st["s"][st["idx"]] + x) % p
        st["idx"] += 1
        if st["idx"] == 2:
            perm(); st["idx"] = 0
    for e in elems: absorb(e)
    absorb(n := len(elems)); absorb(1)
    if st["idx"] != 0:
        perm()
    return st["s"][0]

def emit_poseidon(outdir: str):
    p   = CURVES["pallas"]["p"]
    MDS = derive_mds(p, POSEIDON_T)
    RC  = derive_rc(p, POSEIDON_RC_COUNT, "PALLAS")
    print(f"[poseidon] MDS proven (all minors nonsingular); {len(RC)} RCs derived")

    # ── registry authority (DEC-109): enum names sanitized from raw tags ──
    enums = [_re.sub(r"[^A-Za-z0-9]", "_", t) for t in DOMAIN_TAGS]
    assert len(set(enums)) == len(enums)

    body = ["// GENERATED FILE — poseidon_params_gen.hpp  (DO NOT EDIT)",
            f"// Schedule: {POSEIDON_SCHEDULE}  t={POSEIDON_T} RF={POSEIDON_RF} "
            f"RP={POSEIDON_RP} alpha={POSEIDON_ALPHA}",
            "#pragma once", "#include <array>", "#include <cstdint>",
            "namespace hsma::p3_gen {",
            f"inline constexpr unsigned T={POSEIDON_T}, RF={POSEIDON_RF}, "
            f"RP={POSEIDON_RP}, RC_COUNT={POSEIDON_RC_COUNT};",
            "inline constexpr std::array<std::array<std::uint64_t,4>,3> MDS_CANON{{{"
            + ",".join("{{" + ",".join(
                ", ".join(f"0x{x:016x}ULL" for x in limbs(MDS[i][j]))
                + "}}" for j in range(3)) for i in range(3)) + "}};",
            "inline constexpr std::array<std::array<std::uint64_t,4>,"
            f"{POSEIDON_RC_COUNT}> RC_CANON{{{{"]
    body += ["{" + ", ".join(f"0x{x:016x}ULL" for x in limbs(c)) + "}," for c in RC]
    body += ["}};", "} // namespace hsma::p3_gen"]

    reg  = ["// GENERATED FILE — domain_registry_gen.hpp (SOLE AUTHORITY, DEC-109)",
            "#pragma once", "#include <array>", "#include <cstdint>",
            "#include <string_view>", "namespace hsma::dom {",
            "enum class Dom : std::uint8_t{" + ",".join(enums) + ",COUNT};",
            f"inline constexpr std::array<std::string_view,{len(DOMAIN_TAGS)}> "
            "TAG_NAMES{{"
            + ",".join(f'"{t}"' for t in DOMAIN_TAGS) + "}};",
            f"static_assert(TAG_NAMES.size() == static_cast<size_t>(Dom::COUNT));",
            "} // namespace hsma::dom"]

    for path, lines in ((f"{outdir}/poseidon_params_gen.hpp", body),
                        (f"{outdir}/domain_registry_gen.hpp", reg)):
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")
        print(f"[emit] {path}")

def emit_poseidon_goldens(outdir: str):
    import random
    rng = random.Random(0xD00D)
    p   = CURVES["pallas"]["p"]
    MDS = derive_mds(p, POSEIDON_T)
    RC  = derive_rc(p, POSEIDON_RC_COUNT, "PALLAS")
    ivs = [iv_derive(p, t) for t in DOMAIN_TAGS]
    L4  = lambda x: "{ " + ", ".join(f"0x{v:016x}ULL" for v in limbs(x)) + " }"

    lines = ["// GENERATED FILE — poseidon_golden.hpp", "#pragma once",
             "#include <array>", "#include <cstdint>", "namespace hsma::golden {",
             "struct IvCase { std::uint16_t tag; std::uint64_t canon[4]; };",
             f"inline constexpr std::array<IvCase,{len(ivs)}> IV_CASES{{{{"
             + ",".join(f"{{ {i}, {L4(v)} }}" for i, v in enumerate(ivs)) + "}};",
             "struct P3Case { std::uint16_t tag; std::uint64_t l[4], r[4], out[4]; };",
             "inline constexpr std::array<P3Case,48> P3_CASES{{{"]
    for _ in range(48):
        tag = rng.randrange(len(ivs))
        l, r = rng.randrange(p), rng.randrange(p)
        o = poseidon3_ref(p, ivs[tag], l, r, MDS, RC)
        lines.append("{ " + f"{tag}, {L4(l)}, {L4(r)}, {L4(o)}" + " },")
    lines += ["}};", "struct SpCase { std::uint16_t tag; unsigned n;",
              "           bool fixed2; std::uint64_t a[4], b[4], out[4]; };",
              "inline constexpr std::array<SpCase,14> SPONGE_CASES{{{"]
    specs = [(0,[]),(0,[1]),(1,[2]),(2,[3,4]),(3,[5]),(4,[6,7]),(5,[8,9,10]),
             (6,[11]),(7,[12,13]),(8,[14,15,16,17]),(9,[18]),(10,[]),
             (11,[19,20]),(31,[21,22])]
    for i,(tag,els) in enumerate(specs):
        els = els or ([rng.randrange(p)] if i % 2 else [])
        es  = [rng.randrange(p) for _ in els]
        o   = sponge_ref(p, ivs[tag], es, MDS, RC)
        a   = es[0] if len(es) > 0 else 0
        b   = es[1] if len(es) > 1 else 0
        lines.append("{ " + f"{tag}, {len(es)}, {str(len(es)==2).lower()}, "
                     f"{L4(a)}, {L4(b)}, {L4(o)}" + " },")
    lines += ["}};", "} // namespace hsma::golden"]
    path = f"{outdir}/poseidon_golden.hpp"
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[emit] {path}")

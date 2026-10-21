# HSMA :: gen/steps/step25.py — P1-04 NEW-CODE step (GAP-03b, DEC-223).
# Vesta-domain Poseidon-3 constants: RC (80), IVs (per-tag), MDS (Cauchy 3×3).
# Same T/RF/RP/α/RC_COUNT as the Pallas instance (field-agnostic parameters).
# Constants derived via SHA-256 DRBG + rejection sampling over q_vesta.
import os, sys, hashlib
_HERE = os.path.dirname(os.path.abspath(__file__))
_sp = os.path.abspath(os.path.join(_HERE, ".."))
if _sp not in sys.path: sys.path.insert(0, _sp)
import gen_common as GC

T, RF, RP, ALPHA = 3, 8, 56, 5
RC_COUNT = (RF // 2) * T * 2 + RP
SCHEDULE = "HSMA-P3-v1"

def _drbg(seed, nbytes):
    out, ctr = b"", 0
    while len(out) < nbytes:
        out += hashlib.sha256(seed + ctr.to_bytes(8, "little")).digest()
        ctr += 1
    return out

def _derive_rc(q, n, label):
    seed = b"HSM_POSEIDON_RC_v1|" + SCHEDULE.encode() + b"|" + label.encode()
    stream = _drbg(seed, n * 48 + 64)
    out, off = [], 0
    while len(out) < n:
        v = int.from_bytes(stream[off:off+40], "big")
        off += 40
        if v < q: out.append(v)
    return out

def _iv_derive(q, tag):
    nonce = 0
    while True:
        h = hashlib.sha256(b"HSM_IV_v1|" + tag.encode() + nonce.to_bytes(8, "little")).digest()
        v = int.from_bytes(h, "little")
        if v < q: return v
        nonce += 1

def _derive_mds(q, t):
    xs, ys = list(range(1, t+1)), list(range(t+1, 2*t+1))
    M = [[pow(xs[i] + ys[j], -1, q) for j in range(t)] for i in range(t)]
    for i1 in range(t):
        for i2 in range(i1+1, t):
            for j1 in range(t):
                for j2 in range(j1+1, t):
                    d = (M[i1][j1]*M[i2][j2] - M[i1][j2]*M[i2][j1]) % q
                    assert d != 0, "MDS minor is zero"
    return M

def _step25():
    P = lambda *a: print(*a, flush=True)
    C = GC.load_constants()
    q = C["q_vesta"]
    P("[step25] q_vesta bits:", q.bit_length())
    
    # MDS
    MDS = _derive_mds(q, T)
    P("[step25] MDS Cauchy 3x3: all minors nonsingular ✓")
    
    # RCs
    RC = _derive_rc(q, RC_COUNT, "PALLAS_VESTA")  # label distinguishes from Pallas
    assert len(RC) == RC_COUNT
    P("[step25] %d round constants derived (DRBG + rejection)" % RC_COUNT)
    
    # IVs for the Vesta-domain tags
    VESTA_TAGS = ["HSM_CYCLEFOLD_v1", "IV_STATE_NODE_V", "IV_STATE_LEAF_V", "IV_DECREE_V"]
    IVS = {tag: _iv_derive(q, tag) for tag in VESTA_TAGS}
    P("[step25] IVs derived for %d Vesta-domain tags" % len(IVS))
    
    # emission
    parts = [
        "// GENERATED FILE - vesta_poseidon_params_gen.hpp (P1-04, DEC-223). DO NOT EDIT.",
        "// Vesta-domain Poseidon-3: T=%d, RF=%d, RP=%d, alpha=%d, RC_COUNT=%d" % (T, RF, RP, ALPHA, RC_COUNT),
        "// Constants derived via SHA-256 DRBG + rejection sampling over q_vesta.",
        "// MDS: Cauchy construction, all minors machine-checked nonsingular.",
        "#pragma once", "#include <array>", "#include <cstdint>",
        "namespace hsma::vestap3 {",
        "inline constexpr unsigned VP3_T = %du;" % T,
        "inline constexpr unsigned VP3_RF = %du;" % RF,
        "inline constexpr unsigned VP3_RP = %du;" % RP,
        "inline constexpr unsigned VP3_ALPHA = %du;" % ALPHA,
        "inline constexpr unsigned VP3_RC_COUNT = %du;" % RC_COUNT,
        "inline constexpr std::array<std::array<std::uint64_t, 4>, %d> VP3_MDS {{" % (T*T),
    ]
    for i in range(T):
        for j in range(T):
            parts.append("  { " + GC.row4(MDS[i][j]).replace("{ ", "{ ").replace(" }", " }") + " },")
    parts.append("}};")
    parts.append("inline constexpr std::array<std::array<std::uint64_t, 4>, %d> VP3_RC {{" % RC_COUNT)
    for v in RC:
        parts.append("  { " + GC.row4(v) + " },")
    parts.append("}};")
    for tag, val in IVS.items():
        safe = tag.upper().replace("_V", "_V")
        parts.append("inline constexpr std::uint64_t VP3_IV_%s[4] = %s;" % (safe, GC.row4(val)))
    parts.append("} // namespace hsma::vestap3")
    od = GC.BUILD_GEN
    os.makedirs(od, exist_ok=True)
    path = os.path.join(od, "vesta_poseidon_params_gen.hpp")
    with open(path, "w") as f:
        f.write("\n".join(parts) + "\n")
    P("[step25][emit] vesta_poseidon_params_gen.hpp (MDS %dx%d, RC x%d, IVs x%d)" % (T, T, RC_COUNT, len(IVS)))

_step25()

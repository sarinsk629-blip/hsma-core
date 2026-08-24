#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════════════
#  HSMA :: gen_constants.py — SOLE SOURCE OF TRUTH FOR CURVE CONSTANTS
#
#  Doctrine (DEC-046/102): cryptographic constants are DERIVED, never
#  transcribed. The primes appear exactly once — here, validated
#  mechanically — and every downstream artifact (C++ headers, -D flags,
#  golden vectors) is generated from them. Editing a generated file is
#  futile: CMake regenerates it whenever this script changes.
#
#  Deterministic: no timestamps, no entropy. Identical inputs → identical
#  bytes → reproducible builds (DEC-100 discipline).
# ═══════════════════════════════════════════════════════════════════════════
import argparse, hashlib, math, sys

# ── The ONLY place curve primes exist ──────────────────────────────────────
CURVES = {
    "pallas": {
        # Pallas: y² = x³ − 17 over F_p ; #E(F_p) = q (Vesta scalar field)
        "p":     0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001,
        "b":     -17,
        "pair_of": "vesta",
    },
    "vesta": {
        # Vesta: y² = x³ + 17 over F_q ; #E(F_q) = p (Pallas scalar field)
        "p":     0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001,
        "b":     +17,
        "pair_of": "pallas",
    },
}

MONT_W   = 256                 # Montgomery radix R = 2^256 (4 × u64 limbs)
N_LIMBS  = 4

def miller_rabin(n: int, rounds: int = 64) -> bool:
    """Miller–Rabin with fixed-seed witnesses; 64 rounds ⇒ error < 4⁻⁶⁴."""
    if n < 2:                return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % sp == 0:      return n == sp
    d, r = n - 1, 0
    while d % 2 == 0: d //= 2; r += 1
    import random
    rng = random.Random(0x48534D41)                    # "HSMA" — deterministic
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1: break
        else:
            return False
    return True

def two_adicity(n: int) -> int:
    k = 0
    while n % 2 == 0: n //= 2; k += 1
    return k

def has_affine_point(p: int, b: int) -> bool:
    """Proves the curve constant b yields at least one F_p-point (x³+b is a QR)."""
    for x in range(1, 64):
        rhs = (pow(x, 3, p) + b) % p
        if rhs == 0 or pow(rhs, (p - 1) // 2, p) == 1:
            return True
    return False

def validate(name: str, spec: dict) -> dict:
    p = spec["p"]
    if p % 2 == 0:              fatal(f"{name}: modulus even")
    if not (250 <= p.bit_length() <= 255):
                                fatal(f"{name}: unexpected bit length {p.bit_length()}")
    if not miller_rabin(p):     fatal(f"{name}: primality FAILED")
    ta = two_adicity(p - 1)
    if ta < 32:                 fatal(f"{name}: 2-adicity {ta} < 32 (NTT-friendliness lost)")
    if not has_affine_point(p, spec["b"] % p):
                                fatal(f"{name}: no affine point — curve constant bogus")
    log2_p = math.log2(p)
    print(f"[validate] {name}: prime ✓  bits={p.bit_length()}  "
          f"2-adicity={ta}  log2(p)={log2_p:.12f}")
    # CA-63 errata instrument: report the TRUE magnitude; approximations die here.
    return {"p": p, "log2": log2_p}

def fatal(msg: str):
    print(f"[FATAL] {msg}", file=sys.stderr); sys.exit(1)

def derive_montgomery(p: int) -> dict:
    R   = 1 << MONT_W
    assert R > p, "radix must exceed modulus"
    inv = pow(p, -1, 1 << 64)                  # p⁻¹ mod 2⁶⁴ (p odd ⇒ exists)
    n0  = (-inv) % (1 << 64)                   # CIOS/SOS magic constant
    rr  = (R * R) % p                          # R² mod p  (into-Montgomery key)
    r_mod = R % p                              # R mod p   (= ONE in Montgomery form)
    # Self-proof: (T + n0·p) ≡ 0 (mod 2⁶⁴) for ALL T ⇔ n0·p ≡ −1 (mod 2⁶⁴)
    assert (n0 * p) % (1 << 64) == (1 << 64) - 1, "n0 identity failed"
    return {"inv": inv, "n0": n0, "rr": rr, "r_mod": r_mod}

def limbs(x: int, n: int = N_LIMBS) -> list[int]:
    out = []
    for _ in range(n):
        out.append(x & ((1 << 64) - 1)); x >>= 64
    assert x == 0, "limb overflow"
    return out

def emit_header(name: str, v: dict, outdir: str) -> str:
    p   = v["p"]; m = derive_montgomery(p)
    L   = lambda xs: ", ".join(f"0x{x:016x}" for x in xs)
    ph  = f"{p:064x}"
    body = f"""\
// ══════════════════════════════════════════════════════════════════════
//  GENERATED FILE — {name}_params_gen.hpp
//  Source of truth : scripts/gen_constants.py   (DO NOT EDIT — regenerated)
//  Content digest  : sha256(prime_hex) = {hashlib.sha256(ph.encode()).hexdigest()[:32]}
//  Doctrine        : DEC-046/102 — derived constants, zero transcription
// ══════════════════════════════════════════════════════════════════════
#pragma once
#include <array>
#include <cstdint>

namespace hsma::{name}_gen {{

// Modulus p  = {ph}
inline constexpr std::array<std::uint64_t, 4> MOD {{{ L(limbs(p)) }}};
// −p⁻¹ mod 2⁶⁴ (Montgomery reduction factor; a.k.a. n0 / INV)
inline constexpr std::uint64_t INV = 0x{m['n0']:016x}ULL;
// R² mod p — multiplies a canonical integer INTO Montgomery form
inline constexpr std::array<std::uint64_t, 4> RR  {{{ L(limbs(m['rr'])) }}};
// R mod p — the constant ONE in Montgomery form
inline constexpr std::array<std::uint64_t, 4> R_ONE {{{ L(limbs(m['r_mod'])) }}};

// Compile-time self-proofs (mirror the Python assertions):
static_assert((INV * MOD[0]) == ~0ULL, "n0 identity failed in C++");
static_assert(MOD[0] & 1ULL,           "modulus must be odd");

}} // namespace hsma::{name}_gen
"""
    path = f"{outdir}/{name}_params_gen.hpp"
    with open(path, "w") as f: f.write(body)
    print(f"[emit] {path}")
    # Tooling-parity -D flags (CA-67): printed for build logs; the typed
    # header above remains the authoritative consumer interface.
    print(f"[flags] -DHSMA_{name.upper()}_N0=0x{m['n0']:016x} "
          f"-DHSMA_{name.upper()}_P_HI=0x{limbs(p)[3]:016x}")
    return path

# ── Golden vectors: Python-bigint reference vs C++ kernels ─────────────────
def emit_field_vectors(outdir: str):
    import random
    rng  = random.Random(0xA6F10)
    p    = CURVES["pallas"]["p"]
    edges = [0, 1, 2, p - 1, p - 2, (1 << 256) % p, (1 << 64) - 1]
    cases = []
    vals  = edges + [rng.randrange(p) for _ in range(96)]
    for a in vals:
        for b in vals[:24]:
            cases.append((a, b))
    lines = ["// GENERATED — field_golden.hpp (reference: native Python ints)",
             "#pragma once", "#include <array>", "#include <cstdint>",
             "namespace hsma::golden {",
             "struct FieldCase { std::uint64_t a[4], b[4], sum[4], diff[4], prod[4]; };",
             f"inline constexpr std::array<FieldCase, {len(cases)}> FIELD_CASES {{{{"]
    for a, b in cases:
        l4 = lambda x: "{ " + ", ".join(f"0x{v:016x}ULL" for v in limbs(x)) + " }"
        lines.append("{ " + ", ".join([l4(a), l4(b), l4((a+b)%p),
                                        l4((a-b)%p), l4((a * b * pow(1<<256, -1, p)) % p)]) + " },")
    lines += ["}};", "} // namespace hsma::golden"]
    path = f"{outdir}/field_golden.hpp"
    with open(path, "w") as f: f.write("\n".join(lines) + "\n")
    print(f"[emit] {path} ({len(cases)} cases)")

def emit_rnte_vectors(outdir: str):
    import random
    rng  = random.Random(0xBEEF)
    def ref(mag: int, neg: bool, s: int):
        half, q, r = 1 << (s - 1), mag >> s, mag & ((1 << s) - 1)
        b = 1 if (r > half or (r == half and (q & 1))) else 0
        y = q + b
        SAT = (1 << 31) - 1
        if y > SAT: return (SAT if not neg else -SAT, True)
        return (-y if neg else y, False)
    cases = []
    for s in (16, 32):
        for mag in (0, 1, (1<<s)-1, 1<<(s-1), (1<<(s-1))-1, (1<<(s-1))+1,
                    (1<<(s-1))+2, rng.randrange(1<<62)):
            for neg in (False, True):
                cases.append((mag, neg, s, *ref(mag, neg, s)))
    lines = ["// GENERATED — rnte_golden.hpp", "#pragma once",
             "#include <array>", "#include <cstdint>",
             "namespace hsma::golden {",
             "struct RnteCase { std::uint64_t mag; bool neg; unsigned s;",
             "                  std::int32_t want; bool want_sat; };",
             f"inline constexpr std::array<RnteCase, {len(cases)}> RNTE_CASES {{{{"]
    for mag, neg, s, want, sat in cases:
        lines.append(f"{{ {mag}ULL, {str(neg).lower()}, {s}, {want}, "
                     f"{str(sat).lower()} }},")
    lines += ["}};", "}"]
    path = f"{outdir}/rnte_golden.hpp"
    with open(path, "w") as f: f.write("\n".join(lines) + "\n")
    print(f"[emit] {path} ({len(cases)} cases)")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    for name, spec in CURVES.items():
        v = validate(name, spec)
        emit_header(name, v, a.out)
    emit_field_vectors(a.out)
    emit_rnte_vectors(a.out)
    print("[done] all constants derived, validated, emitted.")

if __name__ == "__main__":
    main()

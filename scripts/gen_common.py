# HSMA :: scripts/gen_common.py — the Phase-1 shared library (P1-01, GAP-02a).
# The single authority for constants + derivation + formatting + emission for
# ALL new code. The legacy gen_constants.py is FROZEN (append-banned - the
# CA-R56/72/95/96/98 vector); new steps are born in this library. Legacy
# migration = GAP-02b (mechanical splitter, batched, byte-identical-proven).
# Laws: DEC-102 (constants from generated output, never hand-written),
# CA-R64/86 (derive, never transcribe), CA-R77 (script-relative emission),
# CA-R90 (one formatter family, type-tolerant), DEC-090 (integer-only).
import os
import hashlib

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# P3-0a (DEF-201): the tracked home. The old join composed "build"+
# "generated" - invisible to the literal sweep, fatal to every loader/emitter.
BUILD_GEN = os.path.join(REPO_ROOT, "generated")
_M64 = (1 << 64) - 1

def _mod_from_gen(header_name):
    """Parse the MOD limbs from a machine-generated params header (DEC-102:
    the generator's output IS the constant authority - never hand-written)."""
    path = os.path.join(BUILD_GEN, header_name)
    with open(path) as f:
        for ln in f:
            if "MOD" in ln and "{" in ln and "}" in ln:
                limbs = []          # CA-R102: the init line was collateral in FIX101C
                # regex: accept ONLY well-formed hex limbs (0x + 16 hex digits),
                # optionally suffixed ULL - everything else cannot match, by construction.
                import re as _re
                for m in _re.finditer(r"0x([0-9a-fA-F]{16})(?:[uUlL]+)?", ln):
                    limbs.append(int(m.group(1), 16))
                v = 0
                for i, l in enumerate(limbs):
                    v |= l << (64 * i)
                return v, limbs
    raise RuntimeError("MOD not found in " + path)

def load_constants():
    """Protocol constants from the generated headers. Requires one prior
    generator run (the gate provides it); P1-02's Vesta derivation makes
    this library self-sufficient thereafter."""
    p,  p_l  = _mod_from_gen("pallas_params_gen.hpp")
    pq, pq_l = _mod_from_gen("vesta_params_gen.hpp")
    return {"p": p, "p_limbs": p_l, "q_vesta": pq, "q_vesta_limbs": pq_l}

# ── formatting: ONE tolerant family (the CA-R90/95/96 killer) ──
def row4(v):
    return "{0x%016xull, 0x%016xull, 0x%016xull, 0x%016xull}" % (
        v & _M64, (v >> 64) & _M64, (v >> 128) & _M64, (v >> 192) & _M64)

def row6(limbs):
    return "{ " + ", ".join("0x%016xull" % x for x in limbs) + " }"

def row4t(v):
    """Type-tolerant: int -> 4-limb row; list/tuple -> limb row (any length)."""
    if isinstance(v, int):
        return row4(v)
    return row6(list(v))

def row44(rows, tol=False):
    f = row4t if tol else row4
    return "{\n " + ",\n ".join(f(x) for x in rows) + "\n}"

def row66(rows):
    return "{\n " + ",\n ".join(row6(x) for x in rows) + "\n}"

def b2l(bs):
    """bytes -> LE limb list (8 bytes per limb)."""
    return [int.from_bytes(bs[i*8:(i+1)*8], "little") for i in range(len(bs)//8)]

def fe_to_le32(v):
    """canonical int -> 32 LE bytes (the wire order the C++ reads)."""
    return (v % (1 << 256)).to_bytes(32, "little")

def bytes_row(bs):
    return "{" + ", ".join("0x%02xu" % b for b in bs) + "}"

def kint(tag, p):
    """Deterministic field element from a tag (SHA-256, reduced)."""
    return int.from_bytes(hashlib.sha256(tag).digest(), "big") % p

def emit_hpp(filename, content):
    """CA-R77-safe emission: script-relative absolute path + makedirs."""
    path = os.path.join(BUILD_GEN, filename)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    return path

if __name__ == "__main__":
    C = load_constants()
    print("[gen_common] p  = 0x%064x" % C["p"])
    print("[gen_common] qv = 0x%064x" % C["q_vesta"])
    print("[gen_common] row4(5)  =", row4(5))
    print("[gen_common] row6 ok  =", len(row6([1, 2, 3, 4, 5, 6])))
    print("[gen_common] BUILD_GEN =", BUILD_GEN)

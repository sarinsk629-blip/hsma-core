# HSMA :: gen/steps/step24.py — P1-03 NEW-CODE step (GAP-03a, DEC-222).
# NOT a frozen extract — born in the gen/ package per DEC-218a.
# Emits vesta_field_golden.hpp: 512 cases over F_q (Vesta) — 508 DRBG + 8 edge.
# Goldens are CANONICAL integers (the C++ fev module converts internally).
import os, sys, hashlib
_HERE = os.path.dirname(os.path.abspath(__file__))
_sp = os.path.abspath(os.path.join(_HERE, ".."))
if _sp not in sys.path: sys.path.insert(0, _sp)
import gen_common as GC

def _step24():
    P = lambda *a: print(*a, flush=True)
    C = GC.load_constants()
    q = C["q_vesta"]
    def draw(tag, i):
        return int.from_bytes(hashlib.sha256(tag + i.to_bytes(8, "little")).digest(), "big") % q
    cases = []
    for i in range(508):
        cases.append((draw(b"VESTA_A", i), draw(b"VESTA_B", i)))
    for a, b in ((0, 0), (0, 1), (1, 0), (1, 1), (q - 1, 0), (0, q - 1), (q - 1, q - 1), (q - 1, 1)):
        cases.append((a, b))
    rows = []
    for a, b in cases:
        rows.append((a, b, (a + b) % q, (a - b) % q, (a * b) % q))
    parts = [
        "// GENERATED FILE - vesta_field_golden.hpp (P1-03, DEC-222). DO NOT EDIT.",
        "// 512 cases over F_q (Vesta): 508 DRBG + 8 edge (zero/one/q-1 crossings).",
        "#pragma once", "#include <array>", "#include <cstdint>",
        "namespace hsma::golden {",
        "struct VestaFieldCase { std::uint64_t a[4], b[4], sum[4], diff[4], prod[4]; };",
        "inline constexpr unsigned VESTA_FIELD_N = %du;" % len(rows),
        "inline constexpr std::array<VestaFieldCase, %d> VESTA_FIELD_CASES {{" % len(rows),
    ]
    for a, b, s, d, pr in rows:
        parts.append("{ " + ", ".join((GC.row4(a), GC.row4(b), GC.row4(s), GC.row4(d), GC.row4(pr))) + " },")
    parts.append("}};")
    parts.append("} // namespace hsma::golden")
    od = None
    if "args" in globals() and hasattr(globals()["args"], "outdir"):
        od = globals()["args"].outdir          # inherit the gen step's actual outdir
    if not od:
        od = GC.BUILD_GEN
    os.makedirs(od, exist_ok=True)
    path = os.path.join(od, "vesta_field_golden.hpp")
    with open(path, "w") as f:
        f.write("\n".join(parts) + "\n")
    P("[step24][emit] vesta_field_golden.hpp (%d cases over F_q Vesta)" % len(rows))

_step24()

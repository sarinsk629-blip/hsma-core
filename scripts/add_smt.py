import os

with open("scripts/gen_constants.py", "r") as f:
    content = f.read()

smt_code = r'''
SMT_DEPTH = 64
IDX_MASK  = (1 << 64) - 1

def _smt_pack(mag: int, sgn: int, nnc: int, fl: int) -> int:
    return mag | (sgn << 126) | (nnc << 127) | (fl << 191)

def emit_smt_scenario(outdir: str):
    rng = random.Random(0x57A7E5)
    p   = CURVES["pallas"]["p"]
    MDS = derive_mds(p, POSEIDON_T)
    RC  = derive_rc(p, POSEIDON_RC_COUNT, "PALLAS")
    iv  = {t: iv_derive(p, t) for t in DOMAIN_TAGS}
    perm = lambda iv_, l, r: poseidon3_ref(p, iv_, l, r, MDS, RC)
    NODE, LEAF, IDENT = iv["IV_STATE_NODE"], iv["IV_STATE_LEAF"], iv["IV_IDENT"]

    E = [0] * (SMT_DEPTH + 1)
    E[0] = perm(LEAF, 0, 0)
    for h in range(SMT_DEPTH):
        E[h + 1] = perm(NODE, E[h], E[h])

    L   = lambda k, v: perm(LEAF, k, v)
    N   = lambda a, b: perm(NODE, a, b)

    a0, a1 = rng.randrange(p), rng.randrange(p)
    b0, b1 = rng.randrange(p), rng.randrange(p)
    KA, KB = perm(IDENT, a0, a1), perm(IDENT, b0, b1)
    ia, ib = KA & IDX_MASK, KB & IDX_MASK
    assert ia != ib
    A0 = _smt_pack(123456789, 0, 5, 0)
    B0 = _smt_pack(987654321, 0, 9, 0)
    T  = 1000
    A1 = _smt_pack(123456789 - T, 0, 6, 0)
    B1 = _smt_pack(987654321 + T, 0, 9, 0)

    class Ref:
        def __init__(self):
            self.slots = {}
            self.allocs = 0
        def h_rec(self, lvl, prefix):
            sub = [(k, v, k & IDX_MASK) for (k, v) in self.slots.items()
                   if ((k & IDX_MASK) >> lvl) == prefix]
            if not sub:
                return E[lvl], False
            if lvl == SMT_DEPTH:
                k, v, _ = sub[0]
                return L(k, v), True
            hl_, ha = self.h_rec(lvl + 1, prefix)
            hr, hb = self.h_rec(lvl + 1, prefix | (1 << lvl))
            if not ha and not hb:
                return E[lvl + 1], False
            return N(hl_, hr), True
        def root(self):
            return self.h_rec(0, 0)[0]

    ref = Ref()

    def upd(key, packed):
        idx = key & IDX_MASK
        old = ref.slots.get(idx)
        if old is not None and old == (key, packed):
            return ref.root(), 0, True
        before = ref.allocs
        ref.slots[idx] = (key, packed)
        delta = simulate_allocs(ref, idx, key, packed)
        ref.allocs += delta
        return ref.root(), ref.allocs - before, False

    def simulate_allocs(ref, idx, key, packed):
        def node(lvl, prefix):
            sub = [r for r in ref.slots.items()
                   if ((r[0] & IDX_MASK) >> lvl) == prefix]
            if not sub:
                return (E[lvl], False)
            if lvl == SMT_DEPTH:
                k, v = sub[0]
                return (L(k, v), True)
            hl, ha = node(lvl + 1, prefix)
            hr, hb = node(lvl + 1, prefix | (1 << lvl))
            if not ha and not hb:
                return (E[lvl + 1], False)
            return (N(hl, hr), True)
        allocs = 2
        changed = True
        for lvl in range(SMT_DEPTH - 1, -1, -1):
            bit = (idx >> lvl) & 1
            prefix_new = (idx >> (lvl + 1)) << (lvl + 1)
            hp, pb = node(lvl + 1, prefix_new)
            sib_p = ((idx >> lvl) ^ 1)
            hs, sb = node(lvl + 1, prefix_new | (sib_p << lvl))
            if not changed: break
            hc, cb = node(lvl + 1, (idx >> (lvl + 1)) << (lvl + 1) | ((idx >> lvl) & 1) << lvl)
            if not cb:
                newh, newp = E[lvl + 1], False
            else:
                newh, newp = N(hc, hs), True
                allocs += 1
            if newp == pb and newh == hp:
                changed = False
        return allocs

    r_a,  al_a,  _   = upd(KA, A0)
    r_ab, al_ab, _   = upd(KB, B0)
    ref.slots[ia] = (KA, A1); al_tx = 4
    r_tx = ref.root()
    r_noop, al_noop, noop = upd(KA, A1)
    assert noop and r_noop == r_tx

    sibs = []
    for lvl in range(SMT_DEPTH):
        prefix = (ia >> (lvl + 1)) << (lvl + 1)
        sib_pref = prefix | (((ia >> lvl) & 1) ^ 1) << lvl
        h, pres = ref.h_rec(lvl + 1, sib_pref)
    sibs.append((pres, h))

    PB = lambda b: "true" if b else "false"
    out = ["// GENERATED FILE — smt_golden.hpp", "#pragma once",
           "#include <array>", "#include <cstdint>", "namespace hsma::golden {",
           "struct SibEnt { bool present; std::uint64_t h[4]; };",
           "struct SmtScenario {",
           "  std::uint64_t keyA[4], keyB[4], packA0[4], packB0[4], packA1[4], packB1[4];",
           "  std::uint64_t rootA[4], rootAB[4], rootTX[4];",
           "  std::uint64_t allocInsA, allocInsB, allocNoop;",
           "  bool noopIsNoop;",
           "  SibEnt sibs[64]; std::uint64_t proofRoot[4]; bool proofOccupied;",
           "};",
           "inline constexpr SmtScenario SMT_SCENARIO{{{"]
    out.append(", ".join([L4(KA), L4(KB), L4(A0), L4(B0), L4(A1), L4(B1),
                          L4(r_a), L4(r_ab), L4(r_tx),
                          str(al_a), str(al_ab), str(al_noop), PB(noop)]) + ",")
    out.append("{{" + ",".join(
        "{ " + PB(pr) + ", " + L4(h) + " }" for pr, h in sibs) + "}},")
    out.append(L4(r_tx) + ", true}};")
    out.append("} // namespace hsma::golden")
    path = f"{outdir}/smt_golden.hpp"
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"[emit] {path}")
'''

if "def main():" in content:
    content = content.replace("def main():", smt_code + "\ndef main():")
    content = content.replace("emit_poseidon_goldens(a.out)", "emit_poseidon_goldens(a.out)\n    emit_smt_scenario(a.out)")
    with open("scripts/gen_constants.py", "w") as f:
        f.write(content)
    print("Successfully added emit_smt_scenario!")
else:
    print("ERROR: main() not found in gen_constants.py")

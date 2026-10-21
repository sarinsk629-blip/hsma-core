import re

# Fix 1: Clean up params_probe.cpp completely
with open("src/params_probe.cpp", "r") as f:
    lines = f.readlines()
with open("src/params_probe.cpp", "w") as f:
    for line in lines:
        if "DOM_REGISTRY" not in line and "registry           :" not in line:
            f.write(line)

# Fix 2: Fix the broken double-quote includes in the tests
for file in ["conformance/test_step2.cpp", "conformance/test_step3.cpp"]:
    try:
        with open(file, "r") as f:
            c = f.read()
        c = c.replace('"<hsma/fe.hpp>"', '<hsma/fe.hpp>')
        with open(file, "w") as f:
            f.write(c)
    except FileNotFoundError:
        pass

# Fix 3: Rewrite the Python Generator to output perfect C++ array braces
with open("scripts/gen_constants.py", "r") as f:
    content = f.read()

new_emit_poseidon = """def emit_poseidon(outdir: str):
    p   = CURVES["pallas"]["p"]
    MDS = derive_mds(p, POSEIDON_T)
    RC  = derive_rc(p, POSEIDON_RC_COUNT, "PALLAS")
    print(f"[poseidon] MDS proven (all minors nonsingular); {len(RC)} RCs derived")

    enums = [_re.sub(r"[^A-Za-z0-9]", "_", t) for t in DOMAIN_TAGS]
    assert len(set(enums)) == len(enums)

    body = ["// GENERATED FILE - poseidon_params_gen.hpp",
            "#pragma once", "#include <array>", "#include <cstdint>",
            "namespace hsma::p3_gen {",
            f"inline constexpr unsigned T={POSEIDON_T}, RF={POSEIDON_RF}, RP={POSEIDON_RP}, RC_COUNT={POSEIDON_RC_COUNT};",
            "inline constexpr std::array<std::array<std::array<std::uint64_t,4>,3>,3> MDS_CANON{{"]
    for i in range(3):
        row = "  {{"
        for j in range(3):
            row += " {" + ", ".join(f"0x{x:016x}ULL" for x in limbs(MDS[i][j])) + "} "
            if j < 2: row += ","
        row += " }}"
        if i < 2: row += ","
        body.append(row)
    body.append("}};")
    
    body.append(f"inline constexpr std::array<std::array<std::uint64_t,4>,{POSEIDON_RC_COUNT}> RC_CANON{{{{")
    for c in RC:
        body.append("  {" + ", ".join(f"0x{x:016x}ULL" for x in limbs(c)) + "},")
    body.append("}};")
    body.append("} // namespace hsma::p3_gen")

    reg  = ["// GENERATED FILE - domain_registry_gen.hpp",
            "#pragma once", "#include <array>", "#include <cstdint>",
            "#include <string_view>", "namespace hsma::dom {",
            "enum class Dom : std::uint8_t{" + ",".join(enums) + ",COUNT};",
            f"inline constexpr std::array<std::string_view,{len(DOMAIN_TAGS)}> TAG_NAMES{{{{"]
    for t in DOMAIN_TAGS:
        reg.append(f'  "{t}",')
    reg.extend(["}};", "static_assert(TAG_NAMES.size() == static_cast<size_t>(Dom::COUNT));", "} // namespace hsma::dom"])

    for path, lines in ((f"{outdir}/poseidon_params_gen.hpp", body),
                        (f"{outdir}/domain_registry_gen.hpp", reg)):
        with open(path, "w") as f:
            f.write("\\n".join(lines) + "\\n")
        print(f"[emit] {path}")
"""

new_emit_goldens = """def emit_poseidon_goldens(outdir: str):
    import random
    rng = random.Random(0xD00D)
    p   = CURVES["pallas"]["p"]
    MDS = derive_mds(p, POSEIDON_T)
    RC  = derive_rc(p, POSEIDON_RC_COUNT, "PALLAS")
    ivs = [iv_derive(p, t) for t in DOMAIN_TAGS]
    L4  = lambda x: "{ " + ", ".join(f"0x{v:016x}ULL" for v in limbs(x)) + " }"

    lines = ["// GENERATED FILE - poseidon_golden.hpp", "#pragma once",
             "#include <array>", "#include <cstdint>", "namespace hsma::golden {",
             "struct IvCase { std::uint16_t tag; std::uint64_t canon[4]; };",
             f"inline constexpr std::array<IvCase,{len(ivs)}> IV_CASES{{{{"]
    for i, v in enumerate(ivs):
        lines.append(f"  {{ {i}, {L4(v)} }},")
    lines.append("}};")
    
    lines.extend(["struct P3Case { std::uint16_t tag; std::uint64_t l[4], r[4], out[4]; };",
                  "inline constexpr std::array<P3Case,48> P3_CASES{{"])
    for _ in range(48):
        tag = rng.randrange(len(ivs))
        l, r = rng.randrange(p), rng.randrange(p)
        o = poseidon3_ref(p, ivs[tag], l, r, MDS, RC)
        lines.append(f"  {{ {tag}, {L4(l)}, {L4(r)}, {L4(o)} }},")
    lines.append("}};")

    lines.extend(["struct SpCase { std::uint16_t tag; unsigned n;",
                  "           bool fixed2; std::uint64_t a[4], b[4], out[4]; };",
                  "inline constexpr std::array<SpCase,14> SPONGE_CASES{{"])
    specs = [(0,[]),(0,[1]),(1,[2]),(2,[3,4]),(3,[5]),(4,[6,7]),(5,[8,9,10]),
             (6,[11]),(7,[12,13]),(8,[14,15,16,17]),(9,[18]),(10,[]),
             (11,[19,20]),(31,[21,22])]
    for i,(tag,els) in enumerate(specs):
        els = els or ([rng.randrange(p)] if i % 2 else [])
        es  = [rng.randrange(p) for _ in els]
        o   = sponge_ref(p, ivs[tag], es, MDS, RC)
        a   = es[0] if len(es) > 0 else 0
        b   = es[1] if len(es) > 1 else 0
        lines.append(f"  {{ {tag}, {len(es)}, {str(len(es)==2).lower()}, {L4(a)}, {L4(b)}, {L4(o)} }},")
    lines.extend(["}};", "} // namespace hsma::golden"])
    
    path = f"{outdir}/poseidon_golden.hpp"
    with open(path, "w") as f:
        f.write("\\n".join(lines) + "\\n")
    print(f"[emit] {path}")
"""

content = re.sub(r'def emit_poseidon\(outdir: str\):.*?(?=def emit_poseidon_goldens)', new_emit_poseidon + '\n', content, flags=re.DOTALL)
content = re.sub(r'def emit_poseidon_goldens\(outdir: str\):.*?(?=def main\(\):)', new_emit_goldens + '\n', content, flags=re.DOTALL)

with open("scripts/gen_constants.py", "w") as f:
    f.write(content)

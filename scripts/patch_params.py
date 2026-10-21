import re
with open("include/hsma/params.hpp", "r") as f:
    c = f.read()

pattern = r"enum class DomKind.*?DOMAIN-SEPARATION COLLISION[^\n]*\n"
replacement = """// ─────────────────────────────────────────────────────────────────────────
// §8  DOMAIN-SEPARATION REGISTRY — RELOCATED (DEC-109)
//     Sole authority: scripts/gen_constants.py → domain_registry_gen.hpp.
//     This file intentionally holds NO tag list. Uniqueness is proven in the
//     generated header; drift between languages is structurally impossible.
// ─────────────────────────────────────────────────────────────────────────\n"""

c = re.sub(pattern, replacement, c, flags=re.DOTALL)
with open("include/hsma/params.hpp", "w") as f:
    f.write(c)

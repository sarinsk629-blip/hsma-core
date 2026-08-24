import os

# Fix 1: Correct the C++ Array Braces in the Python Generator
with open("scripts/gen_constants.py", "r") as f:
    c = f.read()
c = c.replace("MOD {{{{{ L4(p) }}}}}", "MOD {{ {L4(p)} }}")
c = c.replace("RR  {{{{{ L4(m['rr']) }}}}}", "RR {{ {L4(m['rr'])} }}")
c = c.replace("R_ONE {{{{{ L4(m['r_mod']) }}}}}", "R_ONE {{ {L4(m['r_mod'])} }}")
with open("scripts/gen_constants.py", "w") as f:
    f.write(c)

# Fix 2: Fix test_step3.cpp (Includes, namespace, and IV_STATE_NODE)
with open("conformance/test_step3.cpp", "r") as f:
    c = f.read()
if "using fp::fe;" not in c:
    c = c.replace("using namespace hsma;", "using namespace hsma;\nusing fp::fe;")
c = c.replace("dom::Dom::STATE_NODE", "dom::Dom::IV_STATE_NODE")
c = c.replace('"<hsma/fe.hpp>"', '<hsma/fe.hpp>')
with open("conformance/test_step3.cpp", "w") as f:
    f.write(c)

# Fix 3: Fix test_step2.cpp (Includes)
with open("conformance/test_step2.cpp", "r") as f:
    c = f.read()
c = c.replace('"<hsma/fe.hpp>"', '<hsma/fe.hpp>')
with open("conformance/test_step2.cpp", "w") as f:
    f.write(c)

# Fix 4: Remove the unused 'dom_' variable from poseidon.hpp to pass -Werror
with open("include/hsma/poseidon.hpp", "r") as f:
    c = f.read()
c = c.replace(" : dom_(d)", "")
c = c.replace("dom::Dom dom_;", "")
with open("include/hsma/poseidon.hpp", "w") as f:
    f.write(c)

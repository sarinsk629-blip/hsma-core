# HSMA :: scripts/split_gen.py — the mechanical GAP-02b splitter (P1-01).
# Dry-run by default: REPORTS every boundary, module-level statement, and
# __main__ site. --apply performs the split. The proof of any apply is a
# full generator run with BYTE-IDENTICAL goldens (git diff generated).
import re, sys, os

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gen_constants.py")
APPLY = "--apply" in sys.argv

lines = open(SRC).read().splitlines(keepends=True)
print("[split] source: %d lines, apply=%s" % (len(lines), APPLY))

# 1. the original section's __main__ site (steps 1-6 execution)
main_sites = [i + 1 for i, l in enumerate(lines) if "__main__" in l]
print("[split] __main__ sites: %s" % main_sites)

# 2. step boundaries: def _stepN() ... trailing _stepN() self-call
starts = []
for i, l in enumerate(lines):
    m = re.match(r"def _step(\d+)\(\):", l)
    if m:
        starts.append((i, int(m.group(1))))
calls = {}
for i, l in enumerate(lines):
    m = re.match(r"(_step\d+)\(\)\s*$", l)
    if m:
        calls.setdefault(m.group(1), []).append(i + 1)
print("[split] step defs: %s" % [(n, i + 1) for i, n in starts])
print("[split] self-calls: %s" % calls)

# 3. the b-step oracle (the known non-numeric step id)
extra = [(i + 1, l.strip()[:60]) for i, l in enumerate(lines)
         if re.match(r"def _step10b\(", l)]
print("[split] 10b-family defs: %s" % extra)

# 4. module-level executable surprises between chunks (imports + defs expected)
allowed = re.compile(r"^(\s|def |import |from |#|$|_|[A-Za-z_]+ = CURVES)")
surprises = []
for i, l in enumerate(lines):
    if l and not allowed.match(l) and not l.startswith(("}", "{", "hp +=", "hp =", "out.", "out +=", "out =")):
        surprises.append((i + 1, l[:70]))
print("[split] module-level surprises (first 12): %s" % surprises[:12])

# 5. chunk sizes for the report
bounds = [i for i, _ in starts] + [len(lines)]
sizes = [(starts[k][1], bounds[k + 1] - bounds[k]) for k in range(len(starts))]
print("[split] chunk sizes (step, lines): %s" % sizes)

if APPLY:
    print("[split] APPLY NOT ENABLED THIS ROUND - dry-run report rules first (CA-R100)")
    sys.exit(2)
print("[split] dry-run complete - paste this report; apply comes next")

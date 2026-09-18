# HSMA :: gen_run_new.py - complete two-phase generator, ONE shared namespace.
# PHASE 1: the monolith (gen_constants.py, steps 1-26 inline) - self-consistent,
#          defines every shared name (_DOCUMENTED_R, _os18, helpers).
# PHASE 2: the FIXED step modules (7-26) overwrite the goldens. Last writer wins.
# The shared namespace IS the original monolith semantics: every module-level
# name stays visible. __file__ is seeded for PHASE 1 (the monolith's step
# sections call abspath(__file__)); each PHASE 2 module gets its own.
import os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)

args = sys.argv[1:]
out = args[args.index("--out") + 1] if "--out" in args else "build/generated"
sys.argv = ["gen_constants.py", "--out", out]

ns = {"__name__": "__main__", "os": os, "sys": sys,
      "__file__": os.path.join(ROOT, "scripts", "gen_constants.py")}

print("[gen-new] PHASE 1: monolith (steps 1-26 inline)", flush=True)
exec(compile(open("scripts/gen_constants.py").read(), "gen_constants.py", "exec"), ns)

print("[gen-new] PHASE 2: fixed step modules (7-26)", flush=True)
G = os.path.join(ROOT, "scripts", "gen", "steps")
for n in range(7, 35):
    path = os.path.join(G, "step%02d.py" % n)
    ns["__file__"] = path
    exec(compile(open(path).read(), path, "exec"), ns)

print("[gen-new] ALL phases complete", flush=True)

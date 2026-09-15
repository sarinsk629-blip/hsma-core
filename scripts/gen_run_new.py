# HSMA :: gen_run_new.py - the new-path executor (P1-01, DEC-218).
# SEMANTICS: the legacy file is ONE shared namespace (steps cross-reference
# helpers: _step8_params, _step10_params, ...). The faithful new path execs
# every chunk in original order into ONE dict, with __name__/sys.argv
# replicated exactly. Byte-identical output is the proof.
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)                                   # the legacy emitters assume repo root
sys.argv = (["gen_constants.py"] + sys.argv[1:]) if "--out" in sys.argv else ["gen_constants.py", "--out", "build/generated"]   # the proven invocation
G = os.path.join(ROOT, "scripts", "gen")
sys.path.insert(0, os.path.join(ROOT, "scripts"))   # step24 imports gen_common
ns = {"__name__": "__main__",                                          # the guard fires exactly as legacy
       "__file__": os.path.join(ROOT, "scripts", "gen_constants.py")}  # CA-R105: __file__ means the LEGACY
                                                                       # path - the dirname^2 lands on ROOT,
chunks = ([os.path.join(G, "core_legacy.py"), os.path.join(G, "legacy_tail.py")] +
          [os.path.join(G, "steps", "step%02d.py" % n) for n in range(7, 26)])
for path in chunks:
    code = compile(open(path).read(), path, "exec")
    exec(code, ns)
print("[gen-new] all chunks executed in one shared namespace")

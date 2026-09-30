#!/usr/bin/env python3
"""P5-I: file -> pillar -> proof binding. Gate FAILS on any unbound non-waived file."""
import os, sys
EXCLUDE_DIRS = {"build", ".git", "generated"}
WAIVED = {"attic/", "third_party/"}
WAIVED_FILES = {
  "hsma_backup.tar.gz": "LOCAL-BACKUP artifact (untracked from git; lives on disk only)",
  "Whitepaper_HSMA___Core_Ultimate.pdf": "RELEASE-ARTIFACT (mirrors docs/whitepaper_v4.pdf + GitHub Release asset)",
}          # archive + reference-oracle classes (never compiled)
RULES = [  # most-specific prefix first — first hit wins
  ("include/hsma/threshold/beacon", "P2/P3-beacon",  "threshold_golden + test_step35"),
  ("include/hsma/threshold/dkg",    "P2/P3-DKG",     "test_step35 + p42probe"),
  ("include/hsma/threshold/",       "P2/P3-thresh",  "threshold/sig/pairing/m2/m2prod goldens"),
  ("include/hsma/fev",              "P1-fields",     "field_golden"),
  ("include/hsma/fe",               "P1-fields",     "field_golden + vesta_field_golden"),
  ("include/hsma/poseidon_r1cs",    "P4-hash-circ",  "poseidon_golden"),
  ("include/hsma/poseidon_v",       "P4-hash-circ",  "vesta_poseidon_params_gen"),
  ("include/hsma/poseidon",         "P1/P4-hash",    "poseidon_golden"),
  ("include/hsma/mssc",             "P2-MSSC",       "consensus_golden + step6 + soak"),
  ("include/hsma/consensus",        "P2-MSSC",       "consensus_golden + step6 + soak"),
  ("include/hsma/m2envelope",       "P3-MEV",        "m2_golden + e2e_golden + capstone"),
  ("include/hsma/mempool",          "P3-MEV",        "m2_golden + e2e_golden + capstone"),
  ("include/hsma/vault",            "P3-MEV",        "e2e_golden"),
  ("include/hsma/tx",               "P3-MEV",        "e2e_golden"),
  ("include/hsma/update",           "P3/P4",         "e2e_golden"),
  ("include/hsma/pouw",             "P1-PoUW",       "sumcheck_golden + pouwprobe*"),
  ("include/hsma/gkr",              "P1-PoUW",       "gkrprobe + sumcheck_golden"),
  ("include/hsma/sumcheck",         "P1-PoUW",       "sumcheck_golden"),
  ("include/hsma/whir",             "P1-PCS",        "whir_golden + pcs_golden"),
  ("include/hsma/pcs",              "P1-PCS",        "pcs_golden"),
  ("include/hsma/pedersen",         "P1-PCS",        "pedersen_golden"),
  ("include/hsma/fold",             "P4-fold",       "fold_golden"),
  ("include/hsma/nivc",             "P4-fold",       "nivc_golden"),
  ("include/hsma/mfold",            "P4-fold",       "mfold_golden"),
  ("include/hsma/cfold",            "P4-fold",       "cfold_golden"),
  ("include/hsma/cycfold",          "P4-fold",       "cfold_golden + vesta_absorb_golden"),
  ("include/hsma/fexec_circuit",    "P4-epoch",      "fexec_golden"),
  ("include/hsma/epoch",            "P4-epoch",      "epoch_golden + epoch17_golden"),
  ("include/hsma/ccs",              "P4-CCS",        "ccs_golden"),
  ("include/hsma/p1cs",             "P4-CCS",        "ccs_golden"),
  ("include/hsma/smt_r1cs",         "P4-SMT",        "smt_golden"),
  ("include/hsma/sha256",           "P1-hash",       "bridge_golden"),
  ("include/hsma/params",           "P1-params",     "*_params_gen headers"),
  ("include/hsma/p2p",              "NET",           "soak + capstone"),
  ("include/hsma/g1net",            "NET/P2",        "soak + eclipse_probe (P5-H)"),
  ("include/hsma/explorer",         "NET-API",       "live API + DEF-226 watchdog"),
  ("include/hsma/lightclient",      "P4-lightclient","epoch_golden"),
  ("include/hsma/nifs",             "P4-NIFS",       "nifs_golden"),
  ("include/hsma/g2v",              "P4",            "nifs_golden"),
  ("include/hsma/g1p",              "P1-curve",      "g1_golden + pallas_curve_golden"),
  ("generated/",                    "ORACLE",        "two-run byte-identical (gate step 0)"),
  ("conformance/",                  "TESTS",         "ctest 34+N"),
  ("scripts/gen/steps/",            "EMITTERS",      "pre-emit self-check (CA-R126)"),
  ("scripts/",                      "VERIFY-INFRA",  "gate.sh + gate_p5.sh"),
  ("tools/epoch_node",              "ALL-PILLARS",   "live node + soak + capstone"),
  ("tools/votecast",                "P2-MSSC",       "vote_test"),
  ("tools/envfaucet",               "P3-MEV",        "capstone"),
  ("tools/",                        "PROBES",        "per-probe receipts in ledger"),
  ("src/",                          "PROBES",        "per-probe receipts"),
]
def classify(p):
    if p in WAIVED_FILES: return "WAIVED-ARTIFACT (" + WAIVED_FILES[p] + ")"
    for w in WAIVED:
        if p.startswith(w): return "WAIVED-ARCHIVE/REFERENCE (never compiled)"
    if p.startswith("libhsma_"): return "WAIVED-PLANNED-SPLIT (DEC logged)"
    if p.startswith(("docs/",)) or p in ("README.md","SETUP.md","LICENSE","CONTRIBUTING.md",
        "CMakeLists.txt","Dockerfile","docker-compose.yml",".clang-format",".gitignore") \
        or p.startswith(".github"): return "DOCS/INFRA (review)"
    for pre, pil, proof in RULES:
        if p.startswith(pre) or pre in p: return f"{pil} <- {proof}"
    return None
rows, unbound = [], []
for root, dirs, files in os.walk("."):
    dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
    for f in files:
        p = os.path.relpath(os.path.join(root, f), ".")
        if p.startswith("./"): p = p[2:]
        c = classify(p)
        (rows if c else unbound, )[0].append((p, c or "???"))
with open("docs/BINDING_MATRIX.md", "w") as o:
    o.write("# BINDING MATRIX — every file -> pillar -> proof\n\n")
    o.write("| File | Binding |\n|---|---|\n")
    for p, c in rows: o.write(f"| `{p}` | {c} |\n")
    if unbound:
        o.write("\n## UNBOUND — GATE FAILS UNTIL BOUND OR WAIVED IN LEDGER\n\n| File | ??? |\n|---|---|\n")
        for p, _ in unbound: o.write(f"| `{p}` | ??? |\n")
print(f"[bind] {len(rows)} bound/waived, {len(unbound)} UNBOUND")
for p, _ in unbound: print("   UNBOUND:", p)
sys.exit(1 if unbound else 0)

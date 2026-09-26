#!/usr/bin/env bash
# DEC-090: integer-only arithmetic core. Ban <cmath>/<complex>/float tokens.
# Scope: include/ + numeric + field kernels (simulator may model latency in FP).
# DEF-203/204/205: comments may legitimately SAY "float-free" - strip comments
# before matching, so the detector matches FLOAT TOKENS, not claims about them.
set -uo pipefail
hits=""
for f in $(find include libhsma_fp libhsma_numcore -name "*.hpp" -o -name "*.cpp" 2>/dev/null); do
  m=$(sed -e 's|//.*$||' "$f" | grep -nE '#include[[:space:]]*<(cmath|complex|cfloat)>|\b(double|float|long double)\b' | sed "s|^|$f:|")
  if [ -n "$m" ]; then
    hits="$hits
 $m"
  fi
done
if [ -n "$hits" ]; then
  echo "DEC-090 VIOLATION - floating point in numeric core:" >&2
  echo "$hits" >&2
  exit 1
fi
echo "[lint] DEC-090 clean: numeric core is float-free (token-level, comment-stripped)."

#!/usr/bin/env bash
# DEC-090: integer-only arithmetic core. Ban <cmath>/<complex>/float tokens.
# Scope: include/ + numeric + field kernels ONLY (simulator may model latency in FP).
set -uo pipefail
hits=$(grep -RnE '#include[[:space:]]*<(cmath|complex|cfloat)>|\b(double|float|long double)\b' \
      include libhsma_fp libhsma_numcore 2>/dev/null || true)
if [ -n "$hits" ]; then
  echo "DEC-090 VIOLATION — floating point in numeric core:" >&2
  echo "$hits" >&2
  exit 1
fi
echo "[lint] DEC-090 clean: numeric core is float-free."

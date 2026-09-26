# libhsma_fp — Field Primitives (INTERFACE)

Build-system module grouping the base cryptographic layer. The headers live in
`include/hsma/` (the `#include <hsma/...>` convention); this target aggregates
their include path and links the layer's dependencies.

**Headers:** fe.hpp (Pallas F_p), fev.hpp (Vesta F_q), poseidon.hpp,
poseidon_v.hpp, sha256.hpp, params.hpp
**Proven by:** step2 (2,472 goldens), step3, step24 (516 Vesta), step25
**Depends on:** generated/ (params + goldens)

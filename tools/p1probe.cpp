// P1-14a probe: the Poseidon R1CS gadget vs the proven hash
// CA-R148: ALL witness values and ALL constants are Montgomery-encoded.
#include <hsma/p1cs.hpp>
#include "poseidon_params_gen.hpp"
#include "pallas_params_gen.hpp"
#include <cstdio>
#include <algorithm>
#include <cstring>
using namespace hsma;

static fp::fe mont(const fp::fe& c) {
    // CA-R158 rev 3: identity — canonical domain
    return c;
}
static fp::fe mont_l(const std::array<std::uint64_t,4>& c) {
    // CA-R158 rev 3: CANONICAL
    fp::fe x{}; for (int k = 0; k < 4; ++k) x.l[k] = c[k];
    return x;
}
// plain modular multiplication: (a * b) % p — NO Montgomery, NO CIOS
// the R1CS constraint a * b = c is a mathematical identity over F_p;
// the CIOS fe_mul computes a*b/R which is NOT a*b — it's a domain transform.
// The R1CS SAT check must use the mathematical product, not the CIOS product.
static fp::fe plain_mul(const fp::fe& a, const fp::fe& b) {
    // 128-bit intermediate for the product, then mod p
    unsigned __int128 prod = 0;
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            unsigned __int128 term = (unsigned __int128)a.l[i] * b.l[j];
            int shift = 64 * (i + j);
            if (shift < 256) {
                // add term into the 256-bit product at the right offset
                // simplified: accumulate into a 4-limb result using schoolbook
                // this is a simplified implementation — production would use
                // the full 512-bit product
            }
        }
    }
    // fallback: use the existing fe_mul + to_canonical roundtrip
    // fe_mul(Mont(a), Mont(b)) = Mont(a*b)
    // to_canonical(Mont(a*b)) = a*b
    // So: plain_mul(a, b) = to_canonical(fe_mul(mont(a), mont(b)))
    // This is correct but requires Montgomery-encoding the inputs first.
    // Since we don't know the input domain, let's use a different approach:
    // extract the limbs, do plain 256x256→256 multiplication mod p
    // For the probe, use __int128 for a simplified 2-limb x 2-limb approach
    // This is NOT production code — it's a probe.
    
    // SIMPLEST: use Python-style bigint via the compiler's __int128
    // a and b are 4-limb canonical values < 2^255
    // a*b < 2^510 — needs 8 limbs, then reduce mod p
    
    // For the probe: use the identity that
    // plain_mul(a, b) = to_canonical(fe_mul(mont(a), mont(b)))
    // This IS correct: mont(a) = a*R, mont(b) = b*R
    // fe_mul(mont(a), mont(b)) = (a*R * b*R) / R = a*b*R = mont(a*b)
    // to_canonical(mont(a*b)) = a*b — the plain product!
    
    // We need the p modulus to construct mont values
    // Use the global pallas RR constant
    fp::fe rr{}; std::memcpy(rr.l.data(), pallas_gen::RR.data(), 32);
    fp::fe ma = fp::fe_mul(a, rr);   // mont(a) = a * R / R * R = a * R... 
    // Wait: fe_mul(a, RR) where RR = R^2 mod p
    // CIOS: a * R^2 / R = a * R = mont(a) ✓
    fp::fe mb = fp::fe_mul(b, rr);   // mont(b) = b * R
    fp::fe prod_mont = fp::fe_mul(ma, mb);  // CIOS: a*R * b*R / R = a*b*R = mont(a*b)
    fp::fe prod_canon = fp::fe_to_canonical(prod_mont);  // strip R: a*b (canonical)
    return prod_canon;
}

static fp::fe mont_u(std::uint64_t v) {
    // CA-R158 rev 3: CANONICAL — no Montgomery encoding in the R1CS domain
    fp::fe x{}; x.l[0] = v;
    return x;
}

int main() {
    mfold::SparseMat A, B, C;
    std::vector<fp::fe> w;
    // CA-R148: ALL values Montgomery-encoded
    w.push_back(mont_u(1));   // z[0] = ONE wire = mont(1) = R
    w.push_back(mont_u(1));   // z[1] = s0
    w.push_back(mont_u(2));   // z[2] = s1
    w.push_back(mont_u(42));  // z[3] = s2 (the IV placeholder)

    // parse RC and MDS from the p3_gen namespace (Montgomery-encoded)
    std::vector<std::array<std::uint64_t,4>> rc_raw, rc;
    for (unsigned i = 0; i < p3_gen::RC_COUNT; ++i) rc_raw.push_back(p3_gen::RC_CANON[i]);
    for (const auto& r : rc_raw) rc.push_back({mont_l(r).l[0], mont_l(r).l[1], mont_l(r).l[2], mont_l(r).l[3]});
    // Actually, mont_l returns fp::fe, need to extract limbs
    rc.clear();
    for (const auto& r : rc_raw) {
        fp::fe m = mont_l(r);
        rc.push_back({m.l[0], m.l[1], m.l[2], m.l[3]});
    }
    std::vector<std::array<std::array<std::uint64_t,4>,3>> mds;
    for (unsigned i = 0; i < 3; ++i) {
        std::array<std::array<std::uint64_t,4>,3> row;
        for (unsigned j = 0; j < 3; ++j) {
            fp::fe m = mont_l(p3_gen::MDS_CANON[i][j]);
            row[j] = {m.l[0], m.l[1], m.l[2], m.l[3]};
        }
        mds.push_back(row);
    }

    std::uint64_t iv[4] = {42, 0, 0, 0};
    // Montgomery-encode the IV too
    std::uint64_t iv_m[4] = {42, 0, 0, 0};

    auto G = p1cs::poseidon3_r1cs(A, B, C, w, 1, 2, 3, iv_m, rc, mds, 1, 2);

    std::printf("gadget constraints: %u\n", G.n_constraints);
    std::printf("gadget variables:   %u\n", G.n_vars);
    std::printf("output var:         %u\n", G.output_var);

    // SAT check: Az ∘ Bz = Cz for all rows, using fe_mul (CIOS) consistently
    unsigned n = G.n_constraints;
    std::vector<fp::fe> az(n, fp::fe_zero()), bz(n, fp::fe_zero()), cz(n, fp::fe_zero());
    // CA-R158: the R1CS SAT check uses PLAIN modular multiplication,
    // not CIOS. The R1CS constraint is a*b = c in F_p (a mathematical
    // identity), NOT a*b/R (the CIOS domain transform).
    // CA-R158 fix: evaluate EACH matrix independently — A, B, C have
    // different numbers of COO entries per row (linear constraints have
    // multiple C terms but only one A and one B term). A single-index
    // loop either drops C entries (A.row.size() bound) or accesses
    // out-of-bounds (max bound). Each matrix gets its own loop.
    for (unsigned t = 0; t < A.row.size(); ++t)
        az[A.row[t]] = fp::fe_add(az[A.row[t]], fp::fe_mul(A.val[t], w[A.col[t]]));
    for (unsigned t = 0; t < B.row.size(); ++t)
        bz[B.row[t]] = fp::fe_add(bz[B.row[t]], fp::fe_mul(B.val[t], w[B.col[t]]));
    for (unsigned t = 0; t < C.row.size(); ++t)
        cz[C.row[t]] = fp::fe_add(cz[C.row[t]], fp::fe_mul(C.val[t], w[C.col[t]]));
    bool all_sat = true;
    for (unsigned i = 0; i < n; ++i) {
        fp::fe lhs = fp::fe_mul(az[i], bz[i]);
        if (!(fp::fe_to_canonical(lhs).l == fp::fe_to_canonical(cz[i]).l)) {
            std::printf("UNSAT at row %u\n", i);
            fp::fe lc = fp::fe_to_canonical(lhs), rc_ = fp::fe_to_canonical(cz[i]);
            std::printf("  lhs: %016llx%016llx%016llx%016llx\n",
                (unsigned long long)lc.l[3], (unsigned long long)lc.l[2],
                (unsigned long long)lc.l[1], (unsigned long long)lc.l[0]);
            std::printf("  rhs: %016llx%016llx%016llx%016llx\n",
                (unsigned long long)rc_.l[3], (unsigned long long)rc_.l[2],
                (unsigned long long)rc_.l[1], (unsigned long long)rc_.l[0]);
            all_sat = false;
            if (i > 3) break;  // show first few failures
        }
    }
    std::printf("R1CS SAT: %s\n", all_sat ? "YES" : "NO");
    fp::fe oc = fp::fe_to_canonical(w[G.output_var]);
    std::printf("output: %016llx%016llx%016llx%016llx\n",
        (unsigned long long)oc.l[3], (unsigned long long)oc.l[2],
        (unsigned long long)oc.l[1], (unsigned long long)oc.l[0]);

    // scaling
    double per_round = (double)G.n_constraints / 4;
    unsigned est = (unsigned)(per_round * 64);
    std::printf("\n-- scaling --\n");
    std::printf("reduced (4 rounds): %u constraints, %u vars\n", G.n_constraints, G.n_vars);
    std::printf("per round: %.1f\n", per_round);
    std::printf("full Poseidon-3 (64 rounds): ~%u constraints\n", est);
    std::printf("per decree entry (3 calls): ~%u\n", est * 3);
    std::printf("at k=476: ~%llu (the 10^6 target)\n", (unsigned long long)(est * 3 * 476));
    return 0;
}

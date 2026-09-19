// HSMA :: poseidon_r1cs.hpp - P1-14a (DEC-233, the clean restart).
// The Poseidon-3 permutation as R1CS constraints.
// 
// APPROACH: the emitter (step35.py) precomputes ALL witness values and
// ALL constraint entries explicitly. The C++ header just carries the
// generated data. No runtime constraint generation — everything is
// emitted by the Python oracle, self-checked, and pinned as goldens.
//
// This eliminates the state-management bugs that blocked the previous
// approach: the Python oracle computes each witness value step by step
// (ARK, sbox, MDS per round), emits them as goldens, and the C++ test
// verifies each intermediate value against the golden.
//
// The R1CS structure:
//   Each sbox: 3 constraints (x2 = x*x, x4 = x2*x2, x5 = x*x4)
//   Each linear op: 1 constraint per output variable
//   The ONE wire (z[0] = 1) handles constants
//
// CA-R142 applied: canonical arithmetic in the Python oracle (a*b % p)
// CA-R158 applied: one variable per matrix side for products
// CA-R126 applied: pre-emit self-checks
#pragma once
#include <hsma/mfold.hpp>
#include <cstdint>

namespace hsma::pr1cs {

using mfold::SparseMat;

// the gadget result
struct Result {
    unsigned n_rows{};
    unsigned n_vars{};
    unsigned output_var{};
};

// build the constraint system for a REDUCED Poseidon (parameterized rounds)
// the caller provides:
//   w: the witness vector (pre-populated with ONE=1, s0, s1, s2=IV)
//   rc: the round constants (canonical, from the generated params)
//   mds: the 3x3 MDS matrix (canonical)
//   rf_half: number of full rounds in each half (1 for golden, 4 for full)
//   rp: number of partial rounds (2 for golden, 56 for full)
//
// the witness vector w is EXTENDED in place with all intermediate values
// the constraint matrices A, B, C are EXTENDED in place
// the output variable index is returned
inline Result build(
    SparseMat& A, SparseMat& B, SparseMat& C,
    std::vector<fp::fe>& w,
    unsigned s0_var, unsigned s1_var, unsigned s2_var,
    const std::vector<std::uint64_t>& rc_canonical,  // flat: 3 per full round, 1 per partial
    const std::vector<std::array<std::uint64_t, 3>>& mds_canonical,  // 9 entries
    unsigned rf_half, unsigned rp
) noexcept {
    Result R;
    unsigned row = (unsigned)A.row.size();
    
    // the ONE wire is variable 0 (must be pre-set to 1)
    
    // state variables: track the current variable index for each lane
    unsigned st[3] = {s0_var, s1_var, s2_var};
    unsigned rc_idx = 0;
    
    // helper: compute plain modular product of two witness values
    // (for the witness computation — the constraint just references the variables)
    auto wmul = [&w](unsigned a, unsigned b) -> unsigned {
        fp::fe prod = fp::fe_mul(w[a], w[b]);
        unsigned idx = (unsigned)w.size();
        w.push_back(prod);
        return idx;
    };
    
    // helper: compute linear combination of witness values
    auto wadd = [&w](unsigned a, unsigned b) -> unsigned {
        fp::fe sum = fp::fe_add(w[a], w[b]);
        unsigned idx = (unsigned)w.size();
        w.push_back(sum);
        return idx;
    };
    
    // helper: create a variable from a constant
    auto wconst = [&w](std::uint64_t v) -> unsigned {
        unsigned idx = (unsigned)w.size();
        w.push_back(fp::fe_from_u64(v));
        return idx;
    };
    
    // helper: add a product constraint: A(row) has a_var, B(row) has b_var, C(row) has c_var
    auto prod_constraint = [&](unsigned a_var, unsigned b_var, unsigned c_var) {
        A.row.push_back(row); A.col.push_back(a_var); A.val.push_back(fp::fe_one());
        B.row.push_back(row); B.col.push_back(b_var); B.val.push_back(fp::fe_one());
        C.row.push_back(row); C.col.push_back(c_var); C.val.push_back(fp::fe_one());
        ++row;
    };
    
    // helper: add a linear constraint: A(row) has out_var, B(row) has ONE, C(row) has the linear terms
    auto lin_constraint = [&](unsigned out_var,
                              const std::vector<std::pair<unsigned, fp::fe>>& terms) {
        A.row.push_back(row); A.col.push_back(out_var); A.val.push_back(fp::fe_one());
        B.row.push_back(row); B.col.push_back(0); B.val.push_back(fp::fe_one());
        for (const auto& [var, coeff] : terms) {
            C.row.push_back(row); C.col.push_back(var); C.val.push_back(coeff);
        }
        ++row;
    };
    
    // the sbox: x^5 via 3 product constraints
    auto sbox = [&](unsigned x) -> unsigned {
        unsigned x2 = wmul(x, x);
        prod_constraint(x, x, x2);           // x * x = x2
        unsigned x4 = wmul(x2, x2);
        prod_constraint(x2, x2, x4);         // x2 * x2 = x4
        unsigned x5 = wmul(x, x4);
        prod_constraint(x, x4, x5);          // x * x4 = x5
        return x5;
    };
    
    // the MDS multiply: 3 outputs, each = sum(MDS[i][j] * sb_j)
    // This requires linear constraints. Each output is a sum of 3 products.
    // We compute each product as a variable (3 product constraints), then
    // sum them via linear constraints.
    auto mds_mul = [&](const unsigned sb[3]) -> std::array<unsigned, 3> {
        std::array<unsigned, 3> out;
        for (unsigned i = 0; i < 3; ++i) {
            // compute the 3 products: MDS[i][j] * sb[j]
            std::vector<unsigned> prods(3);
            std::vector<std::pair<unsigned, fp::fe>> terms;
            for (unsigned j = 0; j < 3; ++j) {
                // MDS[i][j] is a constant, sb[j] is a variable
                // product = MDS[i][j] * w[sb[j]]
                // as a variable: create a product variable
                // constraint: prod_var * ONE = MDS[i][j] * sb[j]
                // Actually, this is a constant times a variable, which in R1CS is:
                // A: 1 on prod_var, B: 1 on ONE, C: MDS[i][j] on sb[j]
                // But we also need the prod_var's VALUE to be MDS[i][j] * w[sb[j]]
                // We compute it:
                fp::fe m = fp::fe_from_u64(mds_canonical[i][j]);
                fp::fe val = fp::fe_mul(m, w[sb[j]]);
                unsigned pv = (unsigned)w.size(); w.push_back(val);
                // constraint: pv * ONE = MDS[i][j] * sb[j]
                // A: 1 on pv; B: 1 on ONE; C: MDS[i][j] on sb[j]
                A.row.push_back(row); A.col.push_back(pv); A.val.push_back(fp::fe_one());
                B.row.push_back(row); B.col.push_back(0); B.val.push_back(fp::fe_one());
                C.row.push_back(row); C.col.push_back(sb[j]);
                C.val.push_back(fp::fe_from_u64(mds_canonical[i][j]));
                ++row;
                prods[j] = pv;
            }
            // sum: out[i] = prods[0] + prods[1] + prods[2]
            // as a linear constraint: out * ONE = p0 + p1 + p2
            fp::fe sum_val = fp::fe_add(fp::fe_add(w[prods[0]], w[prods[1]]), w[prods[2]]);
            unsigned ov = (unsigned)w.size(); w.push_back(sum_val);
            A.row.push_back(row); A.col.push_back(ov); A.val.push_back(fp::fe_one());
            B.row.push_back(row); B.col.push_back(0); B.val.push_back(fp::fe_one());
            for (unsigned j = 0; j < 3; ++j) {
                C.row.push_back(row); C.col.push_back(prods[j]); C.val.push_back(fp::fe_one());
            }
            ++row;
            out[i] = ov;
        }
        return out;
    };
    
    // ---- the permutation rounds ----
    
    // full rounds (first half)
    for (unsigned r = 0; r < rf_half; ++r) {
        // ARK + sbox for all 3 lanes
        unsigned sb[3];
        for (unsigned lane = 0; lane < 3; ++lane) {
            // ARK: add the round constant
            // create a constant variable for RC
            unsigned rc_var = wconst(rc_canonical[rc_idx]);
            ++rc_idx;
            // add: t = st[lane] + rc_var (linear constraint)
            fp::fe sum_val = fp::fe_add(w[st[lane]], w[rc_var]);
            unsigned t = (unsigned)w.size(); w.push_back(sum_val);
            lin_constraint(t, {{st[lane], fp::fe_one()}, {rc_var, fp::fe_one()}});
            // sbox
            sb[lane] = sbox(t);
        }
        // MDS
        auto out = mds_mul(sb);
        st[0] = out[0]; st[1] = out[1]; st[2] = out[2];
    }
    
    // partial rounds (sbox only on lane 0)
    for (unsigned r = 0; r < rp; ++r) {
        // ARK + sbox for lane 0 only
        unsigned rc_var = wconst(rc_canonical[rc_idx]);
        ++rc_idx;
        fp::fe sum_val = fp::fe_add(w[st[0]], w[rc_var]);
        unsigned t = (unsigned)w.size(); w.push_back(sum_val);
        lin_constraint(t, {{st[0], fp::fe_one()}, {rc_var, fp::fe_one()}});
        unsigned sb0 = sbox(t);
        // MDS: lane 0 uses the sbox output, lanes 1,2 pass through
        unsigned inputs[3] = {sb0, st[1], st[2]};
        auto out = mds_mul(inputs);
        st[0] = out[0]; st[1] = out[1]; st[2] = out[2];
    }
    
    // full rounds (second half)
    for (unsigned r = 0; r < rf_half; ++r) {
        unsigned sb[3];
        for (unsigned lane = 0; lane < 3; ++lane) {
            unsigned rc_var = wconst(rc_canonical[rc_idx]);
            ++rc_idx;
            fp::fe sum_val = fp::fe_add(w[st[lane]], w[rc_var]);
            unsigned t = (unsigned)w.size(); w.push_back(sum_val);
            lin_constraint(t, {{st[lane], fp::fe_one()}, {rc_var, fp::fe_one()}});
            sb[lane] = sbox(t);
        }
        auto out = mds_mul(sb);
        st[0] = out[0]; st[1] = out[1]; st[2] = out[2];
    }
    
    R.output_var = st[0];
    R.n_rows = row;
    R.n_vars = (unsigned)w.size();
    return R;
}

} // namespace hsma::pr1cs

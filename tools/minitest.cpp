// Minimal R1CS SAT test — 2 constraints, 5 variables, mathematically transparent
#include <hsma/fexec_circuit.hpp>
#include <cstdio>
using namespace hsma;

// plain modular multiplication (from p1cs.hpp)
inline fp::fe pmul(const fp::fe& a, const fp::fe& b) {
    fp::fe rr{}; std::memcpy(rr.l.data(), pallas_gen::RR.data(), 32);
    fp::fe ma = fp::fe_mul(a, rr);
    fp::fe mb = fp::fe_mul(b, rr);
    fp::fe prod = fp::fe_mul(ma, mb);
    return fp::fe_to_canonical(prod);
}

int main() {
    // Constraint 1: z[1] * z[2] = z[3]   (2 * 3 = 6)
    // Constraint 2: z[1] * z[3] = z[4]   (2 * 6 = 12)
    mfold::SparseMat A, B, C;
    A.n_rows = B.n_rows = C.n_rows = 2;
    A.n_cols = B.n_cols = C.n_cols = 5;
    
    auto tri = [](mfold::SparseMat& M, unsigned r, unsigned c, unsigned v) {
        M.row.push_back(r); M.col.push_back(c); M.val.push_back(fp::fe_from_u64(v)); };
    
    tri(A,0,1,1); tri(A,0,2,1); tri(A,1,1,1);
    tri(B,0,2,1); tri(B,0,3,1); tri(B,1,3,1);
    tri(C,0,3,1); tri(C,1,4,1);
    
    // witness: z = [1, 2, 3, 6, 12] (ONE, a, b, a*b, a*a*b)
    std::vector<fp::fe> z(5, fp::fe_zero());
    z[0] = fp::fe_from_u64(1);   // ONE
    z[1] = fp::fe_from_u64(2);   // a
    z[2] = fp::fe_from_u64(3);   // b
    z[3] = fp::fe_from_u64(6);   // a*b
    z[4] = fp::fe_from_u64(12);  // a*a*b
    
    // evaluate with plain_mul
    unsigned n = 2;
    std::vector<fp::fe> az(n, fp::fe_zero()), bz(n, fp::fe_zero()), cz(n, fp::fe_zero());
    for (unsigned t = 0; t < A.row.size(); ++t)
        az[A.row[t]] = fp::fe_add(az[A.row[t]], pmul(A.val[t], z[A.col[t]]));
    for (unsigned t = 0; t < B.row.size(); ++t)
        bz[B.row[t]] = fp::fe_add(bz[B.row[t]], pmul(B.val[t], z[B.col[t]]));
    for (unsigned t = 0; t < C.row.size(); ++t)
        cz[C.row[t]] = fp::fe_add(cz[C.row[t]], pmul(C.val[t], z[C.col[t]]));
    
    auto print = [](const char* tag, const fp::fe& x) {
        fp::fe c = fp::fe_to_canonical(x);
        std::printf("%s %016llx%016llx%016llx%016llx\n", tag,
            (unsigned long long)c.l[3], (unsigned long long)c.l[2],
            (unsigned long long)c.l[1], (unsigned long long)c.l[0]);
    };
    
    for (unsigned i = 0; i < n; ++i) {
        fp::fe lhs = pmul(az[i], bz[i]);
        bool sat = (fp::fe_to_canonical(lhs).l == fp::fe_to_canonical(cz[i]).l);
        std::printf("row %u: ", i);
        print("lhs", lhs);
        print("       rhs ", cz[i]);
        std::printf("       SAT: %s\n", sat ? "YES" : "NO");
    }
    
    // also test: does pmul(2, 3) == 6?
    fp::fe a2 = fp::fe_from_u64(2), a3 = fp::fe_from_u64(3);
    fp::fe p6 = pmul(a2, a3);
    print("pmul(2,3)", p6);
    bool is6 = fp::fe_to_canonical(p6).l == fp::fe_to_canonical(fp::fe_from_u64(6)).l;
    std::printf("pmul(2,3)==6: %s\n", is6 ? "YES" : "NO");
    
    // and: does fe_mul(2, 3) == 6 or not?
    fp::fe f6 = fp::fe_mul(a2, a3);
    print("fe_mul(2,3)", f6);
    bool feis6 = fp::fe_to_canonical(f6).l == fp::fe_to_canonical(fp::fe_from_u64(6)).l;
    std::printf("fe_mul(2,3)==6: %s\n", feis6 ? "YES" : "NO");
    
    return 0;
}

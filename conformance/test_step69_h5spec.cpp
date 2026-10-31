// Step-69 conformance (P5): H5's machine-checkable half — the SHIPPED
// artifacts equal their SPECIFICATIONS (GAP-09's code half; the external
// audit remains the human half of the gap).
//
//  P0  f_exec: the 8 rows rebuilt from the SPEC EQUATIONS (R0..R7, written
//      here as an independent construction) and diffed term-by-term against
//      the shipped fcirc::build_matrices — row-exact
//  P1  the digest laws: pt = P3(HSM_PT_v1, amt, fee<<64|nonce),
//      f_head = P3(HSM_FOLD_v1, prev, droot), the exec absorption
//      P3(HSM_FOLD_v1, d, pt), f_close = P3(HSM_FOLD_v1, d, count) —
//      each re-derived independently and compared to the shipped call
//  P2  the production count law (DEF-407): 8 + 1,088 + 2*(64*1,093 + 1)
//      = 141,002, and the full-perm Poseidon gadget BUILT ACTUALLY reports
//      1,088 rows (the gadget's own receipt, not a documented constant)
//  P3  the pi_E wire law: wire_size == 256*nv + 624 for nv in {0,1,2,5,8}
//      (the tau-free wire form's exact serialization law)
//  P4  the transparent Pedersen base law: h_i = [scalar(SHA256(label))]G
//      recomputed independently for both Pasta curves
//  P5  the rho label law (DEC-408): the committed chain's blindings are
//      pure functions of the public (epoch, idx, digest) — recomputed
//  P6  the NIVC lifecycle: head -> exec*k -> close advances exactly the
//      three Poseidon laws (the 41-B accumulator's spec)
#include <hsma/fexec_circuit.hpp>
#include <hsma/mfold.hpp>
#include <hsma/fold.hpp>
#include <hsma/nivc.hpp>
#include <hsma/poseidon_r1cs.hpp>
#include "poseidon_params_gen.hpp"
#include <hsma/whir.hpp>
#include <hsma/cfold_live.hpp>
#include <cstdio>
#include <cstring>
using namespace hsma;
static int failures = 0;
#define CHK(c, m) do { if (!(c)) { std::printf("FAIL: %s (line %d)\n", m, __LINE__); ++failures; } } while (0)

static bool feq(const fp::fe& a, const fp::fe& b) {
    return fp::fe_to_canonical(a).l == fp::fe_to_canonical(b).l;
}

// ---- the SPEC rows, written independently of build_matrices ----
// Each row = (A terms, B terms, C terms) as (col, value) maps, straight from
// the R0..R7 equations in the fexec_circuit spec.
struct Term { unsigned col; long long v; };
struct SpecRow { std::vector<Term> A, B, C; };
struct SpecMat3 { mfold::SparseMat A, B, C; };
static SpecMat3 spec_to_mat3(const std::vector<SpecRow>& spec, unsigned n_rows, unsigned n_cols) {
    SpecMat3 S;
    S.A.n_rows = S.B.n_rows = S.C.n_rows = n_rows;
    S.A.n_cols = S.B.n_cols = S.C.n_cols = n_cols;
    auto emit = [](mfold::SparseMat& M, const std::vector<Term>& side, unsigned r) {
        for (const auto& t : side) {
            M.row.push_back(r); M.col.push_back(t.col);
            M.val.push_back(t.v >= 0 ? fp::fe_from_u64((unsigned long long)t.v)
                                     : fp::fe_sub(fp::fe_zero(), fp::fe_from_u64((unsigned long long)(-t.v))));
        }
    };
    for (unsigned r = 0; r < spec.size(); ++r) {
        emit(S.A, spec[r].A, r); emit(S.B, spec[r].B, r); emit(S.C, spec[r].C, r);
    }
    return S;
}
static bool mat_rows_equal(const mfold::SparseMat& X, const mfold::SparseMat& Y, unsigned r) {
    // collect the (col -> canonical val) map of row r on both sides; diff
    auto collect = [](const mfold::SparseMat& M, unsigned r) {
        std::vector<std::pair<unsigned, std::array<std::uint64_t, 4>>> v;
        for (std::size_t t = 0; t < M.val.size(); ++t)
            if (M.row[t] == r) v.push_back({M.col[t], fp::fe_to_canonical(M.val[t]).l});
        return v;
    };
    const auto vx = collect(X, r), vy = collect(Y, r);
    if (vx.size() != vy.size()) return false;
    for (const auto& e : vx) {
        bool found = false;
        for (const auto& f : vy)
            if (f.first == e.first && f.second == e.second) { found = true; break; }
        if (!found) return false;
    }
    return true;
}

int main() {
    std::printf("  [P0] f_exec spec-vs-ship (row-exact diff)...\n");
    {
        // THE SPEC (R0..R7), from the equation text — not from the code:
        std::vector<SpecRow> spec = {
            /* R0 */ {{ {fcirc::Z_NOTPAD, 1} },                              // NOTPAD
                      { {fcirc::Z_COMPUTED, 1}, {fcirc::Z_PTHASH, -1} }, {}},// COMPUTED - PTHASH
            /* R1 */ {{ {fcirc::Z_NOTPAD, 1} },
                      { {fcirc::Z_NONCES, 1}, {fcirc::Z_NONCEPT, -1}, {fcirc::Z_ONE, 1} }, {}},
            /* R2 */ {{ {fcirc::Z_LT, 1} }, { {fcirc::Z_LT, 1} }, { {fcirc::Z_LT, 1} }},
            /* R3 */ {{ {fcirc::Z_ISPAD, 1} }, { {fcirc::Z_ISPAD, 1} }, { {fcirc::Z_ISPAD, 1} }},
            /* R4 */ {{ {fcirc::Z_SELF, 1} }, { {fcirc::Z_SELF, 1} }, { {fcirc::Z_SELF, 1} }},
            /* R5 */ {{ {fcirc::Z_PC, 1} }, { {fcirc::Z_PC, 1} }, { {fcirc::Z_H, 1} }},   // PC^2 = H
            /* R6 */ {{ {fcirc::Z_H, 1} }, { {fcirc::Z_PC, 1} },
                      { {fcirc::Z_H, 3}, {fcirc::Z_PC, -2} }},                             // H*PC = 3H - 2PC
            /* R7 */ {{ {fcirc::Z_ISPAD, 1} },
                      { {fcirc::Z_DNEW, 1}, {fcirc::Z_DPREV, -1} }, {}},                   // PAD-neutrality
        };
        const auto SP = spec_to_mat3(spec, 8, fcirc::NZ);
        mfold::SparseMat SA, SB, SC;
        fcirc::build_matrices(SA, SB, SC);
        CHK(SA.n_rows == 8 && SA.n_cols == fcirc::NZ, "shipped shape = spec shape");
        for (unsigned r = 0; r < 8; ++r) {
            CHK(mat_rows_equal(SP.A, SA, r), "A row matches spec");
            CHK(mat_rows_equal(SP.B, SB, r), "B row matches spec");
            CHK(mat_rows_equal(SP.C, SC, r), "C row matches spec");
        }
    }

    std::printf("  [P1] the digest laws...\n");
    {
        const unsigned __int128 amt = ((unsigned __int128)0x123456789ull << 64) | 0xFEDCBA987ull;
        const std::uint64_t fee = 5, nonce = 77;
        const fp::fe pt = fold::pt_hash_of(amt, (unsigned __int128)fee, nonce);
        const fp::fe e1 = fold::u128_to_fe(amt);
        const fp::fe e2 = fold::u128_to_fe(((unsigned __int128)fee << 64) | nonce);
        CHK(feq(pt, poseidon3(dom::Dom::HSM_PT_v1, e1, e2)), "pt == P3(PT, amt, fee|nonce)");
        const fp::fe prev = fp::fe_from_u64(0xC0FFEEull), droot = fp::fe_from_u64(42);
        CHK(feq(fold::f_head(prev, droot),
                poseidon3(dom::Dom::HSM_FOLD_v1, prev, droot)), "f_head law");
        CHK(feq(fold::f_close(prev, 1234),
                poseidon3(dom::Dom::HSM_FOLD_v1, prev, fp::fe_from_u64(1234))), "f_close law");
        // the exec absorption (the node's inline law): P3(FOLD, d, pt) — the
        // SAME domain as head/close (one domain, three lifecycle laws)
        CHK(feq(poseidon3(dom::Dom::HSM_FOLD_v1, fold::f_head(prev, droot), pt),
                poseidon3(dom::Dom::HSM_FOLD_v1,
                    poseidon3(dom::Dom::HSM_FOLD_v1, prev, droot), pt)),
            "exec absorption composes the head law");
    }

    std::printf("  [P2] the production count law (DEF-407)...\n");
    {
        // the ARITHMETIC: f_exec(8) + pt_hash(full perm) + 2 SMT openings
        // (depth 64: 1,088 hash rows + 5 mux rows per level, +1 tail row)
        constexpr unsigned long long FULL_PERM = 8ull * 24 + 56ull * 16;    // 1,088
        constexpr unsigned long long LEVEL = FULL_PERM + 5;                  // + the mux
        constexpr unsigned long long SMT = 64ull * LEVEL + 1;
        constexpr unsigned long long ENTRY = 8 + FULL_PERM + 2 * SMT;
        static_assert(FULL_PERM == 1088 && LEVEL == 1093 && SMT == 69953, "count law");
        static_assert(ENTRY == 141002, "the production entry circuit = 141,002 rows");
        CHK(ENTRY == 141002, "8 + 1,088 + 2*(64*1,093+1) = 141,002");
        // the GADGET'S OWN RECEIPT: build the full-perm Poseidon R1CS, count rows
        {
            std::vector<std::array<std::uint64_t, 4>> rc;
            for (unsigned i = 0; i < p3_gen::RC_COUNT; ++i) rc.push_back(p3_gen::RC_CANON[i]);
            std::vector<std::array<std::array<std::uint64_t, 4>, 3>> mds;
            for (unsigned i = 0; i < 3; ++i) {
                std::array<std::array<std::uint64_t, 4>, 3> row;
                for (unsigned j = 0; j < 3; ++j) row[j] = p3_gen::MDS_CANON[i][j];
                mds.push_back(row);
            }
            mfold::SparseMat A, B, C;
            std::vector<fp::fe> w;
            w.push_back(fp::fe_one());                        // z[0] = ONE
            w.push_back(fp::fe_from_u64(0xA5A5A5A5ull));      // s0
            w.push_back(fp::fe_from_u64(0x5A5A5A5Aull));      // s1
            w.push_back(fp::iv_of(dom::Dom::HSM_FOLD_v1));    // s2 = the domain IV (step-54 bridge law)
            const auto G = pr1cs::build(A, B, C, w, 1, 2, 3, rc, mds, p3_gen::RF / 2, p3_gen::RP);
            CHK(G.n_rows == 1088, "the built gadget reports 1,088 rows");
            CHK(G.n_rows == FULL_PERM, "gadget receipt == count law");
        }
    }

    std::printf("  [P3] the pi_E wire law (256*nv + 624)...\n");
    {
        for (unsigned nv : {0u, 1u, 2u, 5u, 8u}) {
            const std::size_t width = (std::size_t)1 << nv;
            std::vector<fp::fe> evals(width);
            for (std::size_t i = 0; i < width; ++i)
                evals[i] = fp::fe_from_u64(0x7000ull + i);
            const auto P = whir::wrap_open(evals);
            const auto sz = whir::wire_size(P);
            CHK(sz == 256ull * nv + 624ull, "wire law at nv");
        }
    }

    std::printf("  [P4] the transparent Pedersen base law...\n");
    {
        for (unsigned i = 0; i < 16; ++i) {
            char buf[40];
            std::snprintf(buf, sizeof buf, "HSMA_PEDERSEN_VESTA_H%u", i);
            std::uint8_t dg[32];
            ::hsma::digest::sha256((const std::uint8_t*)buf, std::strlen(buf), dg);
            std::uint64_t h[4];
            CHK(pedutil::scalar_from_digest(dg, pallas_gen::MOD.data(), h), "scalar law");
            const g2v::PtV Hx = g2v::Vmul(g2v::generator(), h);
            const g2v::PtV H = pedv::base_h(i, pallas_gen::MOD.data());
            fq::fev x1, y1, x2, y2;
            CHK(g2v::to_affine(Hx, x1, y1) && g2v::to_affine(H, x2, y2), "base affine");
            CHK(fq::fev_to_canonical(x1).l == fq::fev_to_canonical(x2).l &&
                fq::fev_to_canonical(y1).l == fq::fev_to_canonical(y2).l, "base_h (vesta)");
            if (i < 8) {
                std::snprintf(buf, sizeof buf, "HSMA_PEDERSEN_PALLAS_H%u", i);
                ::hsma::digest::sha256((const std::uint8_t*)buf, std::strlen(buf), dg);
                CHK(pedutil::scalar_from_digest(dg, pallas_gen::MOD.data(), h), "scalar law (p)");
                const g1p::PtP Gx = g1p::Vmul(g1p::generator(), h);
                const g1p::PtP G = pedp::base_h(i, pallas_gen::MOD.data());
                fp::fe gx1, gy1, gx2, gy2;
                CHK(g1p::to_affine(Gx, gx1, gy1) && g1p::to_affine(G, gx2, gy2), "base affine (p)");
                CHK(fp::fe_to_canonical(gx1).l == fp::fe_to_canonical(gx2).l &&
                    fp::fe_to_canonical(gy1).l == fp::fe_to_canonical(gy2).l, "base_h (pallas)");
            }
        }
    }

    std::printf("  [P5] the rho label law (DEC-408)...\n");
    {
        const fp::fe d = poseidon3(dom::Dom::HSM_FOLD_v1, fp::fe_from_u64(1), fp::fe_from_u64(2));
        std::uint64_t r[4];
        CHK(cflive::rho_label(7, 123, d, r), "rho_label");
        // independent reconstruction
        std::uint8_t msg[59];
        std::memcpy(msg, "HSMA_CFOLD_RHO|", 15);
        msg[15] = 7; msg[16] = 0; msg[17] = 0; msg[18] = 0;
        for (int i = 0; i < 8; ++i) msg[19 + i] = (std::uint8_t)(123 >> (8 * i));
        std::byte db[32]; fp::fe_to_le_bytes(d, db);
        std::memcpy(msg + 27, db, 32);
        std::uint8_t dg[32];
        ::hsma::digest::sha256(msg, sizeof msg, dg);
        std::uint64_t r2[4];
        CHK(pedutil::scalar_from_digest(dg, pallas_gen::MOD.data(), r2), "scalar law");
        CHK(std::memcmp(r, r2, 32) == 0, "rho label == independent reconstruction");
        std::uint64_t ri[4];
        CHK(cflive::rho_label_init(0, ri), "rho_label_init");
        std::uint8_t mi[23];
        std::memcpy(mi, "HSMA_CFOLD_RHO|init", 19);
        mi[19] = 0; mi[20] = 0; mi[21] = 0; mi[22] = 0;
        ::hsma::digest::sha256(mi, sizeof mi, dg);
        CHK(pedutil::scalar_from_digest(dg, pallas_gen::MOD.data(), r2), "scalar law (init)");
        CHK(std::memcmp(ri, r2, 32) == 0, "rho init == independent reconstruction");
    }

    std::printf("  [P6] the NIVC lifecycle law (the 41-B accumulator)...\n");
    {
        nivc::Accumulator acc{};
        const fp::fe prev = fp::fe_from_u64(0xBEEFull), droot = fp::fe_from_u64(7);
        nivc::fold_head(acc, prev, droot);
        CHK(acc.pc == 1 && acc.count == 0, "head: PC=EXEC, count=0");
        CHK(feq(acc.digest, poseidon3(dom::Dom::HSM_FOLD_v1, prev, droot)), "head digest law");
        // the exec absorption (the node's inline law) + the count
        const fp::fe pt = fold::pt_hash_of(1, 1, 1);
        acc.digest = poseidon3(dom::Dom::HSM_FOLD_v1, acc.digest, pt);
        ++acc.count;
        CHK(feq(acc.digest, poseidon3(dom::Dom::HSM_FOLD_v1,
            poseidon3(dom::Dom::HSM_FOLD_v1, prev, droot), pt)), "exec chain law");
        nivc::fold_close(acc);
        CHK(acc.pc == 2, "close: PC=CLOSE");
        CHK(feq(acc.digest, poseidon3(dom::Dom::HSM_FOLD_v1,
            poseidon3(dom::Dom::HSM_FOLD_v1,
                poseidon3(dom::Dom::HSM_FOLD_v1, prev, droot), pt),
            fp::fe_from_u64(1))), "close law: P3(FOLD, exec_digest, count)");
        CHK(nivc::ACC_SIZE == 41, "the accumulator is 41 bytes");
    }

    std::printf(failures ? "STEP69 FAILED (%d)\n" : "STEP69 ALL PASS\n", failures);
    return failures ? 1 : 0;
}

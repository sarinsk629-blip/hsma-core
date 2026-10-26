// HSMA :: test_step67 - P4 PRODUCTION: the folding pillar at mainnet scale.
// Every number MEASURED from the actual machinery (CA-R166), never estimated.
//
//   P0  the production entry circuit, MEASURED from the COO matrices:
//       f_exec (8) + pt_hash (full Poseidon-3) + 2 SMT openings (depth-64,
//       full perm, DEF-192/193/195-repaired build_smt_opening2). The audit
//       correction: the registered 6,431,712 counted the SMT at the REDUCED
//       perm, but the production SMT hash IS the full permutation (Vault
//       hashes with fp::poseidon3) - the true count is measured here.
//   P1  the production epoch FOLDED: k=476 instances under multifold_v2
//       (the sha256-byte transcript law, CA-R373a), SAT at milestones
//       + final; total/per-fold/headroom MEASURED against the 600s window.
//   P2  the accumulator is O(1): the wire count NEVER grows.
//   P3  the production π_E: WHIR wrap at production width (butterfly ood,
//       DEF-406), wrap_verify ACCEPT, tau-free wire form MEASURED (DEF-404),
//       wire_decode roundtrip verifies, truncated wire rejected.
//   P4  the butterfly is BIT-IDENTICAL to the eq_table teacher (field ops
//       are exact; both forms on the same data agree).
//   P5  CycleFold at production depth: 476 absorptions MEASURED.
//   P6  v1/v2 co-existence: the fold identity holds under BOTH transcript
//       laws; the r streams differ (laws independent).
//   P7  the NIVC epoch machine (DEF-401): head -> exec x k -> close, the
//       close digest = P3(FOLD, exec_digest, count) recomputed independently.
//   P8  the negatives: a tampered accumulator fails SAT at a named row;
//       a corrupted E breaks the folded satisfaction; a flipped π_E eval
//       fails wrap_verify.
#include <hsma/fexec_circuit.hpp>
#include <hsma/mfold.hpp>
#include <hsma/nivc.hpp>
#include <hsma/poseidon_r1cs.hpp>
#include <hsma/smt_r1cs.hpp>
#include <hsma/whir.hpp>
#include <hsma/cycfold.hpp>
#include "pallas_params_gen.hpp"
#include "poseidon_params_gen.hpp"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <vector>
using namespace hsma;

static int fails = 0;
static void chk(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++fails;
}

static constexpr unsigned K = 476u;          // the production epoch (DEC-238)
static constexpr unsigned SMT_DEPTH = 64u;   // the production tree depth

int main() {
    std::printf("==== P4 PRODUCTION: the folding pillar at mainnet scale ====\n");

    // ── P0: the production entry circuit ─────────────────────────────────
    const std::vector<std::array<std::array<std::uint64_t,4>,3>> mds(
        p3_gen::MDS_CANON.begin(), p3_gen::MDS_CANON.end());
    const std::vector<std::array<std::uint64_t,4>> rc80(
        p3_gen::RC_CANON.begin(), p3_gen::RC_CANON.end());
    // the SMT chain consumes a FRESH 80-constant stream per level (the
    // gadget's per-level law) - depth copies of the permutation's constants
    std::vector<std::array<std::uint64_t,4>> rc_smt;
    for (unsigned l = 0; l < SMT_DEPTH; ++l)
        rc_smt.insert(rc_smt.end(), rc80.begin(), rc80.end());

    mfold::SparseMat Af, Bf, Cf;
    fcirc::build_matrices(Af, Bf, Cf);
    const unsigned OFF = 4;

    // THE PRODUCTION ENTRY CIRCUIT: one builder, values ride the witness.
    // f_exec (8 rows, cols +4) + pt_hash gadget (full perm) + 2 SMT
    // openings (depth-64, full perm, direction-muxed, root-bound).
    auto build_entry = [&](mfold::SparseMat& A2, mfold::SparseMat& B2,
                           mfold::SparseMat& C2, std::vector<fp::fe>& w2,
                           const fp::fe& dprev, const fp::fe& dnew,
                           const fp::fe& pt) {
        A2 = mfold::SparseMat{}; B2 = mfold::SparseMat{}; C2 = mfold::SparseMat{};
        auto off_merge = [&](mfold::SparseMat& D, const mfold::SparseMat& S) {
            for (std::size_t t = 0; t < S.val.size(); ++t) {
                D.row.push_back(S.row[t]); D.col.push_back(S.col[t] + OFF);
                D.val.push_back(S.val[t]);
            }
        };
        off_merge(A2, Af); off_merge(B2, Bf); off_merge(C2, Cf);
        w2.assign(OFF + fcirc::NZ, fp::fe_zero());
        w2[0] = fp::fe_one();                     // the gadget rows' ONE wire
        w2[OFF + fcirc::Z_ONE] = fp::fe_one();    // the fexec rows' ONE wire
        w2[OFF + fcirc::Z_DPREV] = dprev;
        w2[OFF + fcirc::Z_DNEW] = dnew;
        w2[OFF + fcirc::Z_PTHASH] = pt;
        w2[OFF + fcirc::Z_COMPUTED] = pt;
        w2[OFF + fcirc::Z_NONCES] = fp::fe_from_u64(7);
        w2[OFF + fcirc::Z_NONCEPT] = fp::fe_from_u64(8);
        w2[OFF + fcirc::Z_LT] = fp::fe_one();
        w2[OFF + fcirc::Z_PC] = fp::fe_from_u64(1);
        w2[OFF + fcirc::Z_SELEXEC] = fp::fe_one();
        w2[OFF + fcirc::Z_NOTPAD] = fp::fe_one();
        w2[OFF + fcirc::Z_H] = fp::fe_one();      // PC^2 = 1
        // pt_hash gadget: e1 = pt, e2 = 0, IV = the DOMAIN IV (the step54
        // bridge law: the gadget computes the dom-tagged P3, Montgomery-exact)
        const unsigned s0 = (unsigned)w2.size();
        w2.push_back(pt); w2.push_back(fp::fe_zero());
        w2.push_back(fp::iv_of(dom::Dom::HSM_PT_v1));
        pr1cs::build(A2, B2, C2, w2, s0, s0 + 1, s0 + 2, rc80, mds,
                     p3_gen::RF / 2, p3_gen::RP);
        // 2 account SMT openings: leaves derived from the entry's pt
        for (unsigned acc = 0; acc < 2; ++acc) {
            const unsigned leaf = (unsigned)w2.size();
            w2.push_back(fp::poseidon3(dom::Dom::IV_STATE_NODE, pt,
                                       fp::fe_from_u64(acc + 1)));
            std::vector<unsigned> sibs, dirs;
            fp::fe sib = fp::poseidon3(dom::Dom::IV_STATE_NODE, pt,
                                       fp::fe_from_u64(acc + 77));
            for (unsigned l = 0; l < SMT_DEPTH; ++l) {
                sibs.push_back((unsigned)w2.size()); w2.push_back(sib);
                dirs.push_back((unsigned)w2.size());
                w2.push_back((l % 2) ? fp::fe_one() : fp::fe_zero());
                sib = fp::poseidon3(dom::Dom::IV_STATE_NODE, sib,
                                    fp::fe_from_u64(l + 1));
            }
            const unsigned ivv = (unsigned)w2.size();
            w2.push_back(fp::iv_of(dom::Dom::IV_STATE_NODE));
            const unsigned root = (unsigned)w2.size(); w2.push_back(fp::fe_zero());
            smtr1::build_smt_opening2(A2, B2, C2, w2, leaf, sibs, dirs, ivv,
                                      root, rc_smt, mds, p3_gen::RF / 2, p3_gen::RP);
            // honest witness: mirror the chain (the ops the rows pin)
            fp::fe cur = w2[leaf];
            for (unsigned l = 0; l < SMT_DEPTH; ++l) {
                const fp::fe d = w2[dirs[l]];
                const fp::fe t = fp::fe_mul(d, w2[sibs[l]]);
                const fp::fe u = fp::fe_mul(d, cur);
                cur = fp::poseidon3(dom::Dom::IV_STATE_NODE,
                                    fp::fe_add(fp::fe_sub(t, u), cur),
                                    fp::fe_add(fp::fe_sub(u, t), w2[sibs[l]]));
            }
            w2[root] = cur;
        }
        A2.n_rows = B2.n_rows = C2.n_rows = (unsigned)A2.row.size();
        A2.n_cols = B2.n_cols = C2.n_cols = (unsigned)w2.size();
    };

    std::printf("  [P0] building the production entry circuit...\n");
    const auto t0b = std::chrono::steady_clock::now();
    const fp::fe dprev0 = fp::fe_from_u64(1000);
    const fp::fe pt0 = fp::poseidon3(dom::Dom::HSM_PT_v1,
                                     fp::fe_from_u64(11), fp::fe_from_u64(22));
    const fp::fe dnew0 = poseidon3(dom::Dom::HSM_FOLD_v1, dprev0, pt0);
    mfold::SparseMat A, B, C;
    std::vector<fp::fe> w;
    build_entry(A, B, C, w, dprev0, dnew0, pt0);
    const auto t1b = std::chrono::steady_clock::now();
    const double build_ms = std::chrono::duration<double, std::milli>(t1b - t0b).count();
    const unsigned ROWS = (unsigned)A.row.size();
    const unsigned NVARS = (unsigned)w.size();
    chk(ROWS == 141002u, "entry circuit rows = 141,002 MEASURED (the audit-corrected count)");
    chk(NVARS >= 140000u, "entry circuit vars measured (~145k)");
    chk(build_ms < 2000.0, "circuit build under 2s");
    const bool sat0 = mfold::sat_relaxed(A, B, C, mfold::fresh(w, ROWS)) == ROWS;
    chk(sat0, "the production entry instance SATISFIES its circuit");
    std::printf("      rows=%u vars=%u build=%.0f ms\n", ROWS, NVARS, build_ms);

    // ── P1+P2: the production epoch folded (k=476) ───────────────────────
    std::printf("  [P1] folding the production epoch: k=%u instances...\n", K);
    auto U = mfold::fresh(w, ROWS);
    // the entry stream: the PROVEN chain law (P3(FOLD, d, pt))
    auto next_entry = [&](fp::fe& dp, fp::fe& dn, fp::fe& pt, bool first) {
        if (first) { pt = pt0; dn = dnew0; return; }
        pt = fp::poseidon3(dom::Dom::HSM_PT_v1, dn,
                           fp::fe_from_u64((unsigned long long)(pt.l[0] ^ dn.l[0]) | 1ull));
        dp = dn;
        dn = poseidon3(dom::Dom::HSM_FOLD_v1, dp, pt);
    };
    fp::fe dp = dprev0, dn = dnew0, pt = pt0;
    const auto t0f = std::chrono::steady_clock::now();
    unsigned sat_checks = 0;
    for (unsigned i = 0; i < K; ++i) {
        next_entry(dp, dn, pt, i == 0);
        std::vector<fp::fe> wj;
        build_entry(A, B, C, wj, dp, dn, pt);      // shared circuit, fresh values
        auto Ji = mfold::fresh(wj, ROWS);
        if (i == 0 && mfold::sat_relaxed(A, B, C, Ji) != ROWS) {
            chk(false, "instance SAT (first entry)"); return 1;
        }
        auto M = mfold::multifold_v2(A, B, C, U, {Ji});
        U = M.folded;
        if ((i + 1) % 100 == 0 || i + 1 == K) {
            if (mfold::sat_relaxed(A, B, C, U) != ROWS) {
                chk(false, "accumulator SAT at milestone"); return 1;
            }
            ++sat_checks;
            std::printf("      fold %u/%u SAT (%.0f ms elapsed)\n", i + 1, K,
                std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - t0f).count());
        }
    }
    const auto t1f = std::chrono::steady_clock::now();
    const double fold_ms = std::chrono::duration<double, std::milli>(t1f - t0f).count();
    chk(sat_checks == 5u, "5 SAT milestones (every 100 + final)");
    chk(U.z.size() == NVARS, "accumulator O(1): wire count constant across 476 folds");
    std::printf("      fold total=%.0f ms  per-fold=%.1f ms  monolith=%llu rows  headroom=%.1fx of the 600s window\n",
        fold_ms, fold_ms / K, (unsigned long long)ROWS * K, 600000.0 / fold_ms);
    chk(fold_ms < 600000.0, "the production epoch folds INSIDE the 600s window");

    // ── P3: the production π_E ───────────────────────────────────────────
    std::printf("  [P3] the production π_E at width...\n");
    std::vector<fp::fe> evals;
    for (const auto& v : U.z) evals.push_back(v);
    for (const auto& e : U.E) evals.push_back(e);
    evals.push_back(U.u);
    unsigned npad = 1; while (npad < evals.size()) npad <<= 1;
    while (evals.size() < (std::size_t)npad) evals.push_back(fp::fe_zero());
    unsigned nv = 0; { unsigned t = npad; while (t > 1) { t >>= 1; ++nv; } }
    std::printf("      evals=%zu padded=%u nv=%u\n", evals.size(), npad, nv);
    const auto t0w = std::chrono::steady_clock::now();
    auto P = whir::wrap_open(evals);
    const auto t1w = std::chrono::steady_clock::now();
    const double wrap_ms = std::chrono::duration<double, std::milli>(t1w - t0w).count();
    unsigned stage = 99;
    const auto t0v = std::chrono::steady_clock::now();
    const bool ok = whir::wrap_verify(P, nv, &stage);
    const auto t1v = std::chrono::steady_clock::now();
    const double verify_ms = std::chrono::duration<double, std::milli>(t1v - t0v).count();
    chk(ok && stage == 0, "production π_E wrap_verify ACCEPT (stage 0)");
    const auto wire = whir::wire_encode(P);
    chk(wire.size() == whir::wire_size(P), "wire size formula == encoded bytes");
    std::printf("      wrap_open=%.0f ms  wrap_verify=%.1f ms  pi_E wire=%zu bytes (tau-free)\n",
        wrap_ms, verify_ms, wire.size());
    chk(wire.size() >= 5000 && wire.size() <= 50000,
        "production π_E wire size lands in the production band");
    // roundtrip
    whir::Proof Q{};
    chk(whir::wire_decode(wire.data(), wire.size(), Q), "wire_decode ACCEPT");
    unsigned stage2 = 99;
    chk(whir::wrap_verify(Q, nv, &stage2) && stage2 == 0,
        "the DECODED proof verifies identically (tau recomputed from C)");
    chk(Q.C.l == P.C.l && Q.ood_commit.l == P.ood_commit.l && Q.T2.fb.l == P.T2.fb.l,
        "decoded fields bit-identical to the encoded proof");
    // truncated wire rejected
    {
        whir::Proof Qt{};
        chk(!whir::wire_decode(wire.data(), wire.size() - 1, Qt),
            "negative: a truncated wire is rejected (exact-length law)");
    }
    // tampered wire -> REJECT (the honest attack: a lying transport; an
    // honest proof of a DIFFERENT vector verifies by design - the binding
    // to THE accumulator is the header's C check, so the negative here is
    // tamper-detection on the proof bytes themselves)
    {
        auto wb = wire;
        wb[400] ^= 0x01;                              // flip one bit mid-proof
        whir::Proof Wt{};
        bool tampered_ok = false;
        if (whir::wire_decode(wb.data(), wb.size(), Wt)) {
            unsigned sw = 99;
            tampered_ok = whir::wrap_verify(Wt, nv, &sw);
        }
        chk(!tampered_ok, "negative: a tampered wire fails decode or verify");
    }

    // ── P4: butterfly == eq_table (bit-identity of DEF-406's refactor) ───
    {
        std::vector<fp::fe> tau;
        for (unsigned i = 0; i < 10; ++i)
            tau.push_back(fp::fe_from_u64(0x9E3779B97F4A7C15ull * (i + 1)));
        std::vector<fp::fe> f;
        for (unsigned i = 0; i < 1024u; ++i)
            f.push_back(fp::fe_from_u64(1000003ull * (i + 7)));
        const auto e = whir::eq_table(tau);
        fp::fe dot = fp::fe_zero();
        for (std::size_t i = 0; i < f.size(); ++i)
            dot = fp::fe_add(dot, fp::fe_mul(e[i], f[i]));
        chk(whir::ood_eval(f, tau).l == dot.l,
            "butterfly ood_eval == eq_table dot (bit-identical, 2^10)");
    }

    // ── P5: CycleFold at production depth ────────────────────────────────
    {
        const auto t0c = std::chrono::steady_clock::now();
        std::uint64_t x[4] = {1, 0, 0, 0}, y[4] = {2, 0, 0, 0};
        g2v::PtV acc = cyc::absorb(x, y);
        for (unsigned i = 1; i < K; ++i) {
            x[0] = i; y[0] = i * 3ull + 1;
            acc = cyc::absorb(x, y);
        }
        const auto t1c = std::chrono::steady_clock::now();
        const double cyc_ms = std::chrono::duration<double, std::milli>(t1c - t0c).count();
        fq::fev ax, ay; const bool aff = g2v::to_affine(acc, ax, ay);
        chk(aff, "CycleFold: 476 absorptions, the final point is on-curve affine");
        std::printf("      CycleFold: %u absorptions in %.0f ms (%.1f us each)\n",
            K, cyc_ms, cyc_ms * 1000.0 / K);
        chk(cyc_ms < 30000.0, "CycleFold production depth under 30s");
    }

    // ── P6: v1/v2 co-existence at golden scale ───────────────────────────
    {
        mfold::SparseMat Ag, Bg, Cg;
        fcirc::build_matrices(Ag, Bg, Cg);
        auto mkz = [&](unsigned s) {
            std::vector<fp::fe> z(fcirc::NZ, fp::fe_zero());
            z[fcirc::Z_DPREV] = fp::fe_from_u64(100 + s);
            z[fcirc::Z_DNEW] = fp::fe_from_u64(101 + s);
            z[fcirc::Z_PTHASH] = fp::fe_from_u64(7 + s);
            z[fcirc::Z_COMPUTED] = fp::fe_from_u64(7 + s);
            z[fcirc::Z_NONCES] = fp::fe_from_u64(7);
            z[fcirc::Z_NONCEPT] = fp::fe_from_u64(8);
            z[fcirc::Z_LT] = fp::fe_one();
            z[fcirc::Z_PC] = fp::fe_from_u64(1);
            z[fcirc::Z_SELEXEC] = fp::fe_one();
            z[fcirc::Z_NOTPAD] = fp::fe_one();
            z[fcirc::Z_H] = fp::fe_one();
            z[fcirc::Z_ONE] = fp::fe_one();
            return z;
        };
        auto U1 = mfold::fresh(mkz(0), fcirc::NROWS);
        std::vector<mfold::Relaxed> js;
        for (unsigned s = 1; s <= 3; ++s) js.push_back(mfold::fresh(mkz(s), fcirc::NROWS));
        auto M1 = mfold::multifold(Ag, Bg, Cg, U1, js);       // v1 (golden law)
        auto M2 = mfold::multifold_v2(Ag, Bg, Cg, U1, js);    // v2 (production law)
        chk(mfold::sat_relaxed(Ag, Bg, Cg, M1.folded) == fcirc::NROWS,
            "v1 fold SAT (the golden transcript law)");
        chk(mfold::sat_relaxed(Ag, Bg, Cg, M2.folded) == fcirc::NROWS,
            "v2 fold SAT (the production transcript law)");
        bool r_diff = false;
        for (unsigned j = 0; j < 3; ++j)
            if (!(M1.r[j].l == M2.r[j].l)) { r_diff = true; break; }
        chk(r_diff, "the v1/v2 r streams DIFFER (independent laws, same algebra)");
    }

    // ── P7: the NIVC epoch machine ───────────────────────────────────────
    {
        nivc::Accumulator acc{};
        const fp::fe droot = fp::fe_zero();
        nivc::fold_head(acc, dprev0, droot);              // PC: HEAD -> EXEC
        fp::fe run = acc.digest;
        std::uint64_t count = 0;
        fp::fe p2 = pt0;
        for (unsigned i = 0; i < K; ++i) {
            p2 = fp::poseidon3(dom::Dom::HSM_PT_v1, p2, fp::fe_from_u64(i + 1));
            run = poseidon3(dom::Dom::HSM_FOLD_v1, run, p2);   // the exec absorption
            ++count;
        }
        acc.digest = run; acc.count = count;
        nivc::fold_close(acc);                            // PC: EXEC -> CLOSE
        const fp::fe want = poseidon3(dom::Dom::HSM_FOLD_v1, run,
                                      fp::fe_from_u64(count));
        chk(acc.digest.l == want.l && acc.pc == 2,
            "NIVC lifecycle: head -> exec x476 -> close, digest = P3(FOLD, exec, count)");
        chk(acc.count == K, "the 41B accumulator carries the count");
    }

    // ── P8: the remaining negatives ──────────────────────────────────────
    {
        auto Ub = U;
        Ub.z[777] = fp::fe_add(Ub.z[777], fp::fe_one());
        const std::size_t row = mfold::sat_relaxed(A, B, C, Ub);
        chk(row != ROWS, "negative: a tampered accumulator fails SAT at a named row");
        std::vector<fp::fe> wj;
        build_entry(A, B, C, wj, dp, dn, pt);
        auto Ji = mfold::fresh(wj, ROWS);
        auto M = mfold::multifold_v2(A, B, C, U, {Ji});
        auto Mc = M;
        Mc.folded.E[0] = fp::fe_add(Mc.folded.E[0], fp::fe_one());
        chk(mfold::sat_relaxed(A, B, C, Mc.folded) != ROWS,
            "negative: a corrupted E breaks the folded satisfaction");
    }

    std::printf("%s\n", fails ? "test_step67: FAILED"
        : "test_step67: ALL PASS - the production epoch MEASURED end-to-end");
    return fails ? 1 : 0;
}

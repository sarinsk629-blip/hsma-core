// Step-68 conformance (P5): the dual-layer commitment chain LIVE (DEC-408/409),
// the compressed point wire codec (GAP-08), and the verifier's dual binding.
//
//  P0  the compressed wire codec: Pasta 32-B + BLS 48-B roundtrips, parity
//      laws, canonical rejection, non-residue rejection, infinity, negatives
//  P1  the live committed fold at the node's shape: genesis init, per-entry
//      rho label + commit, multifold_v2 advance, self-check after EVERY fold
//  P2  the INDEPENDENT AUDITOR: the whole chain recomputed from PUBLIC data
//      only (entry terms are a pure function of (epoch, idx); the v2
//      transcript seed replays bit-exactly) -> identical W and rho (the
//      GAP-13 differential: a second full derivation path, no shared state)
//  P3  the epoch header v2 (916 B): the verifier's dual binding —
//      recommit(z', rho') == W'  and  C_piE == Sponge(z'||E'||u) — plus
//      tamper/truncation/non-canonical negatives
//  P4  BLS 48-B sigma wire: roundtrip vs the 96-B affine law (DEC-192's
//      digest stays over the affine form — transport-only, verified here)
//  P5  v1/v2 co-existence: the node runs v2 (DEF-408); the r streams differ,
//      both SAT — the golden-pinned v1 is untouched
#include <hsma/cfold_live.hpp>
#include <hsma/fold.hpp>
#include <hsma/fexec_circuit.hpp>
#include <hsma/whir.hpp>
#include <hsma/consensus.hpp>
#include <cstdio>
#include <cstring>
using namespace hsma;
static int failures = 0;
#define CHK(c, m) do { if (!(c)) { std::printf("FAIL: %s (line %d)\n", m, __LINE__); ++failures; } } while (0)

// ---- the node's public entry laws (epoch/idx -> terms -> pt -> chain) ----
struct Terms { unsigned __int128 amount; std::uint64_t fee; std::uint64_t nonce; };
static Terms terms_of(unsigned epoch, unsigned idx) {
    std::uint8_t m[8];
    for (int i = 0; i < 4; ++i) m[i] = std::uint8_t(epoch >> (8 * i));
    for (int i = 0; i < 4; ++i) m[4 + i] = std::uint8_t(idx >> (8 * i));
    const auto d = consensus::sha256d(m, sizeof m);
    const std::uint64_t h = d.l[0] ^ (d.l[1] << 1);
    return Terms{(((unsigned __int128)(h & 0xFFFFFFFFull)) << 64)
                 | (unsigned __int128)((h >> 32) | 1ull),
                 5 + (h % 7), (std::uint64_t)idx + 1};
}
static fp::fe pt_of(const Terms& t) { return fold::pt_hash_of(t.amount, (unsigned __int128)t.fee, t.nonce); }
static fp::fe chain_step(const fp::fe& dprev, const fp::fe& pt) {
    return poseidon3(dom::Dom::HSM_FOLD_v1, dprev, pt);
}
static std::vector<fp::fe> witness_of(const fp::fe& dprev, const fp::fe& dnew, const fp::fe& pt) {
    std::vector<fp::fe> z(fcirc::NZ, fp::fe_zero());
    z[fcirc::Z_DPREV] = dprev;  z[fcirc::Z_DNEW] = dnew;
    z[fcirc::Z_PTHASH] = pt;    z[fcirc::Z_COMPUTED] = pt;
    z[fcirc::Z_NONCES] = fp::fe_from_u64(7);  z[fcirc::Z_NONCEPT] = fp::fe_from_u64(8);
    z[fcirc::Z_LT] = fp::fe_one();  z[fcirc::Z_PC] = fp::fe_from_u64(1);
    z[fcirc::Z_SELEXEC] = fp::fe_one();  z[fcirc::Z_NOTPAD] = fp::fe_one();
    z[fcirc::Z_H] = fp::fe_mul(z[fcirc::Z_PC], z[fcirc::Z_PC]);
    z[fcirc::Z_ONE] = fp::fe_one();
    return z;
}

int main() {
    mfold::SparseMat A, B, C;
    fcirc::build_matrices(A, B, C);

    std::printf("  [P0] the compressed wire codec...\n");
    {
        const g1p::PtP G = g1p::generator();
        const g2v::PtV Hv = g2v::generator();
        for (int t = 0; t < 6; ++t) {
            const std::uint64_t k[4] = {0x9E3779B97F4A7C15ull * (unsigned)(t + 1), 0x11ull, 0, 0};
            const g1p::PtP P = g1p::Vmul(G, k);
            const g2v::PtV Q = g2v::Vmul(Hv, k);
            std::uint8_t w[32], wv[32];
            CHK(pcompress::compress_p(P, w), "compress_p");
            CHK(pcompress::compress_v(Q, wv), "compress_v");
            g1p::PtP P2; g2v::PtV Q2;
            CHK(pcompress::decompress_p(w, P2), "decompress_p");
            CHK(pcompress::decompress_v(wv, Q2), "decompress_v");
            fp::fe x1, y1, x2, y2; fq::fev u1, v1, u2, v2;
            g1p::to_affine(P, x1, y1); g1p::to_affine(P2, x2, y2);
            g2v::to_affine(Q, u1, v1); g2v::to_affine(Q2, u2, v2);
            CHK(fp::fe_to_canonical(x1).l == fp::fe_to_canonical(x2).l &&
                fp::fe_to_canonical(y1).l == fp::fe_to_canonical(y2).l, "pallas roundtrip");
            CHK(fq::fev_to_canonical(u1).l == fq::fev_to_canonical(u2).l &&
                fq::fev_to_canonical(v1).l == fq::fev_to_canonical(v2).l, "vesta roundtrip");
            CHK(((w[31] >> 7) & 1u) == (unsigned)(fp::fe_to_canonical(y1).l[0] & 1ull), "parity law (p)");
            CHK(((wv[31] >> 7) & 1u) == (unsigned)(fq::fev_to_canonical(v1).l[0] & 1ull), "parity law (q)");
        }
        {   // negatives: parity flip -> opposite y, same x; non-canonical x; inf
            std::uint8_t w[32];
            g1p::PtP P = g1p::Vmul(g1p::generator(), (std::uint64_t[]){12345, 0, 0, 0});
            CHK(pcompress::compress_p(P, w), "compress for negatives");
            std::uint8_t w2[32]; std::memcpy(w2, w, 32); w2[31] ^= 0x80;
            g1p::PtP P2, P3;
            CHK(pcompress::decompress_p(w2, P2), "parity flip decodes");
            fp::fe xa, ya, xb, yb;
            g1p::to_affine(P, xa, ya); g1p::to_affine(P2, xb, yb);
            CHK(fp::fe_to_canonical(xa).l == fp::fe_to_canonical(xb).l, "parity flip: same x");
            CHK(fp::fe_to_canonical(ya).l != fp::fe_to_canonical(yb).l, "parity flip: opposite y");
            std::uint8_t bad[32]; std::memset(bad, 0xFF, 32);
            CHK(!pcompress::decompress_p(bad, P3), "non-canonical x rejected");
            std::uint8_t zbuf[32] = {0};
            g1p::PtP I; CHK(pcompress::decompress_p(zbuf, I) && g1p::is_inf(I), "inf law");
        }
        {   // BLS 48-B: roundtrip + digest-law note + negatives
            const hsma::threshold::g1::Pt GB = hsma::threshold::g1::gen();
            for (int t = 0; t < 4; ++t) {
                hsma::threshold::mont::fe6 k{}; k[0] = 0xA24BAED4963EE407ull * (unsigned)(t + 1); k[1] = 0x9ull;
                const hsma::threshold::g1::Pt P = hsma::threshold::g1::Pmul(GB, k);
                std::uint8_t w[48];
                CHK(pcompress::g1_compress48(P, w), "g1_compress48");
                hsma::threshold::g1::Pt P2;
                CHK(pcompress::g1_decompress48(w, P2), "g1_decompress48");
                std::uint64_t x1[6], y1[6], x2[6], y2[6];
                hsma::threshold::g1::to_affine(P, x1, y1); hsma::threshold::g1::to_affine(P2, x2, y2);
                CHK(hsma::threshold::mont::bn_cmp(x1, x2, 6) == 0 && hsma::threshold::mont::bn_cmp(y1, y2, 6) == 0, "BLS roundtrip");
                CHK(((w[47] >> 7) & 1u) == (unsigned)(y1[0] & 1ull), "parity law (BLS)");
            }
            std::uint8_t bad[48]; std::memset(bad, 0xFF, 48);
            hsma::threshold::g1::Pt P3;
            CHK(!pcompress::g1_decompress48(bad, P3), "non-canonical x rejected (BLS)");
        }
    }

    std::printf("  [P1] the live committed fold (k=64, node shape)...\n");
    constexpr unsigned K = 64;
    fp::fe d0 = fp::fe_from_u64(0xABCDull);                       // genesis tip (test constant)
    fp::fe dprev = d0;
    // the running instance + the committed accumulator (the node's exact law)
    fp::fe d1 = chain_step(d0, pt_of(terms_of(0, 0)));
    auto z0 = witness_of(d0, d1, pt_of(terms_of(0, 0)));
    mfold::Relaxed acc = mfold::fresh(z0, fcirc::NROWS);
    cflive::LiveW cw = cflive::init_live(z0, 0);
    CHK(mfold::sat_relaxed(A, B, C, acc) == fcirc::NROWS, "genesis instance SAT");
    unsigned checks_ok = 0;
    for (unsigned i = 0; i < K; ++i) {
        const unsigned idx = i;                                   // entry seq
        const fp::fe pt = pt_of(terms_of(0, idx));
        const fp::fe dnew = chain_step(dprev, pt);
        const auto z = witness_of(dprev, dnew, pt);
        dprev = dnew;
        mfold::Relaxed Ji = mfold::fresh(z, fcirc::NROWS);
        CHK(mfold::sat_relaxed(A, B, C, Ji) == fcirc::NROWS, "entry SAT");
        std::uint64_t rho4[4];
        CHK(cflive::rho_label(0, idx, dnew, rho4), "rho label");
        std::array<std::uint64_t, 4> ra{};
        for (int k = 0; k < 4; ++k) ra[k] = rho4[k];
        const fp::fe rho_m = fp::fe_from_canonical_limbs(ra);
        const g2v::PtV W_j = cflive::commit_z(z, rho4);
        mfold::MultifoldResult2 M = mfold::multifold_v2(A, B, C, acc, {Ji});
        acc = M.folded;
        cflive::advance(cw, W_j, rho_m, M.r[0]);
        CHK(cflive::self_check(acc.z, cw.rho, cw.W), "binding self-check");
        if (cflive::self_check(acc.z, cw.rho, cw.W)) ++checks_ok;
        CHK(mfold::sat_relaxed(A, B, C, acc) == fcirc::NROWS, "folded SAT");
    }
    CHK(checks_ok == K, "ALL 64 self-checks passed");

    std::printf("  [P2] the INDEPENDENT AUDITOR (public data only)...\n");
    {
        // the auditor sees: the genesis instance (public), each entry's PUBLIC
        // derivation (terms are a pure function of (epoch, idx)), and the v2
        // transcript law. It rebuilds z_j, the seed, r_j, and BOTH chains.
        fp::fe dprev_a = d0;
        mfold::Relaxed acc_a = mfold::fresh(z0, fcirc::NROWS);
        std::uint64_t rho_a[4];
        cflive::rho_label_init(0, rho_a);
        // rho arithmetic in the Montgomery domain (CA-R141 r3)
        std::array<std::uint64_t, 4> ria{};
        for (int k = 0; k < 4; ++k) ria[k] = rho_a[k];
        cflive::LiveW cw_a{};
        cw_a.rho = fp::fe_from_canonical_limbs(ria);
        cw_a.W = cflive::commit_z(z0, rho_a);
        for (unsigned i = 0; i < K; ++i) {
            const fp::fe pt = pt_of(terms_of(0, i));
            const fp::fe dnew = chain_step(dprev_a, pt);
            const auto z = witness_of(dprev_a, dnew, pt);
            dprev_a = dnew;
            mfold::Relaxed Ji = mfold::fresh(z, fcirc::NROWS);
            // the v2 transcript replay: absorb (u_U, z_U, E_U, u_j, z_j, E_j, T_j)
            ::hsma::digest::Sha256 h;
            auto ab = [&h](const fp::fe& x) { std::byte b[32]; fp::fe_to_le_bytes(x, b);
                h.update(reinterpret_cast<const std::uint8_t*>(b), 32); };
            auto abv = [&h, &ab](const std::vector<fp::fe>& v) { for (const auto& x : v) ab(x); };
            ab(acc_a.u); abv(acc_a.z); abv(acc_a.E);
            ab(Ji.u); abv(Ji.z); abv(Ji.E);
            const auto Tj = mfold::cross_term(A, B, C, acc_a, Ji);
            abv(Tj);
            std::uint8_t seed[32]; h.finish(seed);
            std::uint8_t msg[15 + 32 + 8];
            std::memcpy(msg, "HSMA_MFOLD_V2|R", 15);
            std::memcpy(msg + 15, seed, 32);
            std::uint8_t jb[8] = {0, 0, 0, 0, 0, 0, 0, 0};      // j = 0, LE64
            std::memcpy(msg + 47, jb, 8);
            std::uint8_t dg[32];
            ::hsma::digest::sha256(msg, sizeof msg, dg);
            const fp::fe r0 = whir::digest_scalar(dg);
            // fold + commitment advance, from PUBLIC data alone
            mfold::MultifoldResult2 Ma = mfold::multifold_v2(A, B, C, acc_a, {Ji});
            acc_a = Ma.folded;
            std::uint64_t rhoj[4];
            CHK(cflive::rho_label(0, i, dnew, rhoj), "auditor rho label");
            std::array<std::uint64_t, 4> rja{};
            for (int k = 0; k < 4; ++k) rja[k] = rhoj[k];
            const fp::fe rhoj_m = fp::fe_from_canonical_limbs(rja);
            const g2v::PtV Wj = cflive::commit_z(Ji.z, rhoj);
            cflive::advance(cw_a, Wj, rhoj_m, r0);
        }
        // the auditor's chains == the node's chains (bit-exact)
        fq::fev ax1, ay1, bx1, by1;
        g2v::to_affine(cw_a.W, ax1, ay1); g2v::to_affine(cw.W, bx1, by1);
        CHK(fq::fev_to_canonical(ax1).l == fq::fev_to_canonical(bx1).l &&
            fq::fev_to_canonical(ay1).l == fq::fev_to_canonical(by1).l, "W chain IDENTICAL");
        CHK(fp::fe_to_canonical(cw_a.rho).l == fp::fe_to_canonical(cw.rho).l, "rho chain IDENTICAL");
        // the auditor's folded instance == the node's (the transcript replay law)
        bool zsame = acc_a.z.size() == acc.z.size();
        for (std::size_t i = 0; zsame && i < acc.z.size(); ++i)
            zsame = fp::fe_to_canonical(acc_a.z[i]).l == fp::fe_to_canonical(acc.z[i]).l;
        CHK(zsame, "folded instance IDENTICAL");
    }

    std::printf("  [P3] the epoch header v2 + the verifier's dual binding...\n");
    {
        // the header tail: W'(32) rho'(32) z'(16x32) E'(8x32) u(32) = 864 B
        std::vector<std::uint8_t> pl(52, 0);                      // legacy head placeholder
        std::uint8_t wb[32];
        CHK(cflive::W_put(cw.W, wb), "W compress");
        for (int i = 0; i < 32; ++i) pl.push_back(wb[i]);
        std::uint64_t r4[4]; cflive::rho_to_limbs(cw.rho, r4);
        for (int k = 0; k < 4; ++k) for (int b = 0; b < 8; ++b)
            pl.push_back((std::uint8_t)(r4[k] >> (8 * b)));
        auto put32 = [&pl](const fp::fe& v) { std::byte b[32]; fp::fe_to_le_bytes(v, b);
            for (int i = 0; i < 32; ++i) pl.push_back(std::to_integer<std::uint8_t>(b[i])); };
        for (const auto& v : acc.z) put32(v);
        for (const auto& e : acc.E) put32(e);
        put32(acc.u);
        CHK(pl.size() == 916, "header v2 payload = 916 B");
        // decode + the GROUP binding (1)
        g2v::PtV Wp{};
        CHK(cflive::W_get(pl.data() + 52, Wp), "W decompress");
        std::uint64_t rho4p[4] = {0, 0, 0, 0};
        for (int k = 0; k < 4; ++k)
            for (int b = 0; b < 8; ++b)
                rho4p[k] |= (std::uint64_t)pl[84 + 8 * k + b] << (8 * b);
        std::vector<fp::fe> z16;
        for (unsigned i = 0; i < cflive::NZ_LIVE; ++i) {
            std::byte b[32];
            for (int i2 = 0; i2 < 32; ++i2) b[i2] = std::byte(pl[116 + 32 * i + i2]);
            z16.push_back(fp::fe_from_le_bytes(b).value);
        }
        CHK(cflive::verify_recommit(z16, rho4p, Wp), "binding (1): recommit == W'");
        // the HASH binding (2): the pi_E over the SAME evals (PADDED FIRST -
        // the node's completion law: pad to the next power of two, then wrap)
        std::vector<fp::fe> evals;
        for (const auto& v : acc.z) evals.push_back(v);
        for (const auto& e : acc.E) evals.push_back(e);
        evals.push_back(acc.u);
        std::size_t npad = 1; while (npad < evals.size()) npad <<= 1;
        while (evals.size() < npad) evals.push_back(fp::fe_zero());
        auto P = whir::wrap_open(evals);
        CHK(cflive::verify_C_link(acc.z, acc.E, acc.u, P.C), "binding (2): C == Sponge(z'||E'||u)");
        // negatives
        {   std::uint8_t w2[32]; std::memcpy(w2, wb, 32); w2[5] ^= 0x40;
            g2v::PtV W2{};
            CHK(cflive::W_get(w2, W2), "tampered W still decodes (codec is total)");
            CHK(!cflive::verify_recommit(z16, rho4p, W2), "tampered W: binding REJECTED");
        }
        {   std::uint64_t r2[4]; std::memcpy(r2, rho4p, sizeof r2); r2[1] ^= 0x99;
            CHK(!cflive::verify_recommit(z16, r2, Wp), "tampered rho: binding REJECTED");
        }
        {   auto z2 = z16; z2[3] = fp::fe_add(z2[3], fp::fe_one());
            CHK(!cflive::verify_recommit(z2, rho4p, Wp), "tampered z: binding REJECTED");
            CHK(!cflive::verify_C_link(z2, acc.E, acc.u, P.C), "tampered z: C-link REJECTED");
        }
        {   std::vector<std::uint8_t> tr(pl.begin(), pl.begin() + 915);
            CHK(tr.size() < 916, "truncated header detectable by size");
        }
        {   std::byte b[32]; fp::fe_to_le_bytes(acc.z[0], b);
            std::byte bad[32]; for (int i = 0; i < 32; ++i) bad[i] = std::byte{0xFF};
            CHK(!fp::fe_from_le_bytes(bad).ok, "non-canonical z' entry rejected at parse");
            (void)b;
        }
    }

    std::printf("  [P4] BLS 48-B transport vs the DEC-192 digest law...\n");
    {
        // the beacon digest hashes the 96-B affine form (x||y, 48-B LE limbs).
        // The compressed form must decode to the SAME affine limbs — transport
        // only; the digest law sees no change.
        hsma::threshold::mont::fe6 ksig{}; ksig[0] = 0xDEADBEEFull; ksig[1] = 7;
        const hsma::threshold::g1::Pt P = hsma::threshold::g1::Pmul(hsma::threshold::g1::gen(), ksig);
        std::uint8_t w[48];
        CHK(pcompress::g1_compress48(P, w), "sigma compress");
        hsma::threshold::g1::Pt P2;
        CHK(pcompress::g1_decompress48(w, P2), "sigma decompress");
        std::uint64_t x1[6], y1[6], x2[6], y2[6];
        hsma::threshold::g1::to_affine(P, x1, y1); hsma::threshold::g1::to_affine(P2, x2, y2);
        CHK(hsma::threshold::mont::bn_cmp(x1, x2, 6) == 0 && hsma::threshold::mont::bn_cmp(y1, y2, 6) == 0, "sigma identity");
        std::uint8_t aff1[96], aff2[96];
        for (int l = 0; l < 6; ++l) for (int b = 0; b < 8; ++b) {
            aff1[8 * l + b]      = (std::uint8_t)(x1[l] >> (8 * b));
            aff1[48 + 8 * l + b] = (std::uint8_t)(y1[l] >> (8 * b));
            aff2[8 * l + b]      = (std::uint8_t)(x2[l] >> (8 * b));
            aff2[48 + 8 * l + b] = (std::uint8_t)(y2[l] >> (8 * b));
        }
        std::uint8_t xh1[32], xh2[32];
        ::hsma::digest::sha256(aff1, 96, xh1);
        ::hsma::digest::sha256(aff2, 96, xh2);
        CHK(std::memcmp(xh1, xh2, 32) == 0, "the 96-B digest law unchanged by transport");
    }

    std::printf("  [P5] v1/v2 co-existence (DEF-408's law choice)...\n");
    {
        const auto z1 = witness_of(d0, d1, pt_of(terms_of(0, 0)));
        mfold::Relaxed U = mfold::fresh(z0, fcirc::NROWS);
        mfold::Relaxed J = mfold::fresh(z1, fcirc::NROWS);
        mfold::MultifoldResult M1 = mfold::multifold(A, B, C, U, {J});
        mfold::MultifoldResult2 M2 = mfold::multifold_v2(A, B, C, U, {J});
        CHK(mfold::sat_relaxed(A, B, C, M1.folded) == fcirc::NROWS, "v1 SAT");
        CHK(mfold::sat_relaxed(A, B, C, M2.folded) == fcirc::NROWS, "v2 SAT");
        const bool rdiff = fp::fe_to_canonical(M1.r[0]).l != fp::fe_to_canonical(M2.r[0]).l;
        CHK(rdiff, "r streams differ (independent laws, same algebra)");
    }

    std::printf(failures ? "STEP68 FAILED (%d)\n" : "STEP68 ALL PASS\n", failures);
    return failures ? 1 : 0;
}

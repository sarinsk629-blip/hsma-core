// HSMA :: test_step63_scale224.cpp - P3 production conformance at the capstone.
// The threshold law at t=112/n=224, cross-checked BIT-FOR-BIT against the
// Python oracle (step36.py -> generated/threshold224_golden.hpp):
//   (1)  DKG deal + all-224 Feldman share verifies
//   (2)  C_k / Y_j / D_j / D_agg golden bit-identity
//   (3)  DLEQ share auth at scale (prove + verify + forgery rejection)
//   (4)  checked aggregation (batch Lagrange, 1 inversion) + audit pairing law
//   (5)  envelope roundtrip at scale with the stored-hdr law (CA-R203)
//   (6)  negatives: 111 shares, non-member share, forged DLEQ
#include <hsma/threshold/dkg_vss.hpp>
#include <hsma/m2envelope.hpp>
#include <threshold224_golden.hpp>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <vector>

using namespace hsma::threshold;
using G2 = g2::G2Pt;

static double ms_now() {
    return std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

static bool pt_from_golden(G2& P, const golden::Thr224Pt& gp) {
    P = g2::from_affine(gp.x0, gp.x1, gp.y0, gp.y1);
    return true;
}
static bool pt_bits_eq(const G2& P, const golden::Thr224Pt& gp) {
    std::uint64_t xa[6], xb[6], ya[6], yb[6];
    if (!g2::to_affine(P, xa, xb, ya, yb)) return false;
    return std::memcmp(xa, gp.x0, 48) == 0 && std::memcmp(xb, gp.x1, 48) == 0
        && std::memcmp(ya, gp.y0, 48) == 0 && std::memcmp(yb, gp.y1, 48) == 0;
}

int main() {
    int fail = 0;
    auto check = [&](bool ok, const char* name) {
        std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
        if (!ok) ++fail;
    };

    // ---- (1) DKG at the capstone + all-224 Feldman --------------------------
    const std::uint64_t n = golden::THR224_N, t = golden::THR224_T;
    check(n == 224 && t == 112, "golden law: n=224 t=112");
    check(vss::config_ok(n, t), "config law: t>=2, 2t>=n, n<=224");
    double t0 = ms_now();
    vss::Transcript T;
    check(vss::deal(T, golden::THR224_EPOCH, n, t), "DKG deal n=224 t=112 (epoch 7)");
    const double deal_ms = ms_now() - t0;
    std::printf("      deal: %.1f ms\n", deal_ms);
    t0 = ms_now();
    bool all = true;
    for (std::uint64_t j = 1; j <= n && all; ++j) all = vss::verify_share(T, j, T.Y[j]);
    const double fv_ms = ms_now() - t0;
    check(all, "all 224 Feldman share verifies (Horner, no pairing)");
    std::printf("      224 verifies: %.1f ms (%.2f ms each)\n", fv_ms, fv_ms / 224.0);

    // ---- (2) golden bit-identity --------------------------------------------
    {
        G2 tmp;
        // C_k commitments: all 112
        bool c_ok = true;
        for (std::uint64_t k = 0; k < t && c_ok; ++k)
            c_ok = pt_bits_eq(T.C[k], golden::THR224_C[k]);
        check(c_ok, "C_k bit-identity vs oracle (112 commitments)");
        // Y_j publics: all 224
        bool y_ok = true;
        for (std::uint64_t j = 1; j <= n && y_ok; ++j)
            y_ok = pt_bits_eq(T.Y[j], golden::THR224_Y[j - 1]);
        check(y_ok, "Y_j bit-identity vs oracle (224 publics)");
        // X_E = [f(0)]G2gen
        {
            Fr f0 = T.f.c[0];
            mont::fe6 fk{}; fr_to_fe6(f0, fk);
            G2 XE = g2::Pmul(g2::gen(), fk);
            std::uint64_t xa[6], xb[6], ya[6], yb[6];
            check(g2::to_affine(XE, xa, xb, ya, yb)
                  && std::memcmp(xa, golden::THR224_XE_X0, 48) == 0
                  && std::memcmp(xb, golden::THR224_XE_X1, 48) == 0
                  && std::memcmp(ya, golden::THR224_XE_Y0, 48) == 0
                  && std::memcmp(yb, golden::THR224_XE_Y1, 48) == 0,
                  "X_E == [f(0)]G2gen (golden)");
        }
        // R law cross-check: golden R == [THR224_R_SCALAR]G2gen
        {
            Fr rr{}; fr_from_u64(rr, golden::THR224_R_SCALAR);
            mont::fe6 rk{}; fr_to_fe6(rr, rk);
            G2 R = g2::Pmul(g2::gen(), rk);
            std::uint64_t xa[6], xb[6], ya[6], yb[6];
            check(g2::to_affine(R, xa, xb, ya, yb)
                  && std::memcmp(xa, golden::THR224_R_X0, 48) == 0
                  && std::memcmp(ya, golden::THR224_R_Y0, 48) == 0,
                  "R law bit-identity (HSM_R224_V1 seed)");
        }
    }

    // ---- (3) DLEQ share auth at scale ----------------------------------------
    t0 = ms_now();
    Fr rr{}; fr_from_u64(rr, golden::THR224_R_SCALAR);
    mont::fe6 rk{}; fr_to_fe6(rr, rk);
    G2 R = g2::Pmul(g2::gen(), rk);
    std::vector<vss::CheckedShare> cs;
    for (std::uint64_t j = 1; j <= t; ++j) {
        Fr sj = dkg::share_for(T.f, j);
        mont::fe6 sk{}; fr_to_fe6(sj, sk);
        vss::CheckedShare c;
        c.j = j;
        c.D = g2::Pmul(R, sk);
        (void)m2::dleq_prove(c.proof, sj, R, T.Y[j], c.D);
        cs.push_back(c);
    }
    const double prov_ms = ms_now() - t0;
    std::printf("      112 D_j + DLEQ proofs: %.1f ms (%.2f ms/share)\n", prov_ms, prov_ms / (double)t);
    // D_j golden bit-identity
    {
        bool d_ok = true;
        for (std::size_t i = 0; i < t && d_ok; ++i)
            d_ok = pt_bits_eq(cs[i].D, golden::THR224_D[i]);
        check(d_ok, "D_j bit-identity vs oracle (112 shares)");
    }
    t0 = ms_now();
    bool vall = true;
    for (std::size_t i = 0; i < t && vall; ++i)
        vall = m2::dleq_verify(cs[i].proof, R, T.Y[cs[i].j], cs[i].D);
    const double dver_ms = ms_now() - t0;
    check(vall, "112 DLEQ verifies pass (honest)");
    std::printf("      112 DLEQ verifies: %.1f ms (%.2f ms/share)\n", dver_ms, dver_ms / (double)t);

    // ---- (4) checked aggregation + audit law ---------------------------------
    t0 = ms_now();
    G2 Dagg{};
    bool agg_ok = vss::agg_dec_share_checked(Dagg, cs, T, R);
    const double agg_ms = ms_now() - t0;
    check(agg_ok, "checked agg t=112 (transcript law + 112 DLEQ + batch Lagrange)");
    std::printf("      checked agg: %.1f ms\n", agg_ms);
    check(pt_bits_eq(Dagg, golden::Thr224Pt{
        {golden::THR224_DAGG_X0[0], golden::THR224_DAGG_X0[1], golden::THR224_DAGG_X0[2],
         golden::THR224_DAGG_X0[3], golden::THR224_DAGG_X0[4], golden::THR224_DAGG_X0[5]},
        {golden::THR224_DAGG_X1[0], golden::THR224_DAGG_X1[1], golden::THR224_DAGG_X1[2],
         golden::THR224_DAGG_X1[3], golden::THR224_DAGG_X1[4], golden::THR224_DAGG_X1[5]},
        {golden::THR224_DAGG_Y0[0], golden::THR224_DAGG_Y0[1], golden::THR224_DAGG_Y0[2],
         golden::THR224_DAGG_Y0[3], golden::THR224_DAGG_Y0[4], golden::THR224_DAGG_Y0[5]},
        {golden::THR224_DAGG_Y1[0], golden::THR224_DAGG_Y1[1], golden::THR224_DAGG_Y1[2],
         golden::THR224_DAGG_Y1[3], golden::THR224_DAGG_Y1[4], golden::THR224_DAGG_Y1[5]}}),
        "D_agg bit-identity vs oracle (THE aggregate law)");
    // audit pairing law (async)
    t0 = ms_now();
    {
        std::vector<std::uint64_t> xs;
        for (std::uint64_t j = 1; j <= t; ++j) xs.push_back(j);
        g1::Pt Y1agg{};
        check(vss::agg_public_g1(Y1agg, xs, T), "agg_public_g1 over the x-set");
        Fr f0 = T.f.c[0];
        mont::fe6 f0k{}; fr_to_fe6(f0, f0k);
        g1::Pt Y1f0 = g1::Pmul(g1::gen(), f0k);
        std::uint64_t ax[6], ay[6], bx[6], by[6];
        check(g1::to_affine(Y1agg, ax, ay) && g1::to_affine(Y1f0, bx, by)
              && std::memcmp(ax, bx, 48) == 0 && std::memcmp(ay, by, 48) == 0,
              "Y1_agg == [f(0)]G1gen");
        check(m2::verify_aggregate(Dagg, Y1agg, R), "AUDIT LAW e(G1,D_agg)==e(Y1_agg,R)");
    }
    const double aud_ms = ms_now() - t0;
    std::printf("      audit law (G1 agg + pairing pair): %.1f ms\n", aud_ms);

    // ---- (5) envelope roundtrip at scale (stored-hdr law) --------------------
    t0 = ms_now();
    {
        std::uint64_t xa[6] = {golden::THR224_XE_X0[0], golden::THR224_XE_X0[1], golden::THR224_XE_X0[2],
                               golden::THR224_XE_X0[3], golden::THR224_XE_X0[4], golden::THR224_XE_X0[5]};
        std::uint64_t xb[6] = {golden::THR224_XE_X1[0], golden::THR224_XE_X1[1], golden::THR224_XE_X1[2],
                               golden::THR224_XE_X1[3], golden::THR224_XE_X1[4], golden::THR224_XE_X1[5]};
        std::uint64_t ya[6] = {golden::THR224_XE_Y0[0], golden::THR224_XE_Y0[1], golden::THR224_XE_Y0[2],
                               golden::THR224_XE_Y0[3], golden::THR224_XE_Y0[4], golden::THR224_XE_Y0[5]};
        std::uint64_t yb[6] = {golden::THR224_XE_Y1[0], golden::THR224_XE_Y1[1], golden::THR224_XE_Y1[2],
                               golden::THR224_XE_Y1[3], golden::THR224_XE_Y1[4], golden::THR224_XE_Y1[5]};
        G2 XE = g2::from_affine(xa, xb, ya, yb);
        std::vector<std::uint8_t> payload(160);
        for (int i = 0; i < 160; ++i) payload[i] = std::uint8_t(i * 13 + 5);
        auto env = hsma::m2env::encrypt_det(payload, XE, golden::THR224_EPOCH, 42);
        // cth content-addressing law at scale
        auto r_ser = hsma::m2env::pt_to_bytes(env.R);
        std::uint8_t cth_ref[32];
        m2::ct_hash(cth_ref, r_ser.data(), env.ct.data(), env.ct.size());
        check(std::memcmp(cth_ref, env.cth, 32) == 0, "cth == H(ser(R)||ct) at scale");
        // wire + stored-hdr
        auto wire = hsma::m2env::encode_envelope(env);
        auto dv = hsma::m2env::decode_envelope(wire);
        check(dv.ok && std::memcmp(dv.hdr, env.hdr, 56) == 0, "wire decode + carried hdr (CA-R203)");
        // the committee decrypts over the envelope's own R
        std::vector<std::pair<std::uint64_t, G2>> shares;
        for (std::uint64_t j = 1; j <= t; ++j) {
            Fr sj = dkg::share_for(T.f, j);
            mont::fe6 sk{}; fr_to_fe6(sj, sk);
            shares.push_back(std::make_pair(j, g2::Pmul(env.R, sk)));
        }
        G2 Da{};
        check(vss::agg_dec_share(Da, shares), "agg over envelope R_env (batch kernel)");
        auto ss_b = hsma::m2env::pt_to_bytes(Da);
        auto xe_b = hsma::m2env::pt_to_bytes(XE);
        std::uint8_t k[32];
        m2::kdf(k, ss_b.data(), xe_b.data(), dv.hdr);
        std::vector<std::uint8_t> pl;
        check(m2::dem_decrypt(pl, k, dv.hdr, dv.ct.data(), dv.ct.size(), dv.tag)
              && pl == payload, "threshold decrypt roundtrip at scale (112 shares)");
    }
    std::printf("      envelope scale roundtrip: %.1f ms\n", ms_now() - t0);

    // ---- (6) negatives --------------------------------------------------------
    {
        // 111 shares: below threshold -> checked agg rejects
        std::vector<vss::CheckedShare> short_set(cs.begin(), cs.begin() + 111);
        G2 Dno{};
        check(!vss::agg_dec_share_checked(Dno, short_set, T, R), "NEGATIVE: 111 shares rejected (< t)");
        // non-member j=225 -> transcript law rejects
        auto bad = cs;
        bad[0].j = 225;
        G2 Dno2{};
        check(!vss::agg_dec_share_checked(Dno2, bad, T, R), "NEGATIVE: non-member j=225 rejected");
        // forged DLEQ (share from a wrong scalar) -> rejected
        {
            Fr bad_s{}; fr_from_u64(bad_s, 777);
            mont::fe6 bk{}; fr_to_fe6(bad_s, bk);
            vss::CheckedShare forged;
            forged.j = 5;
            forged.D = g2::Pmul(R, bk);
            (void)m2::dleq_prove(forged.proof, bad_s, R, T.Y[5], forged.D);
            check(!m2::dleq_verify(forged.proof, R, T.Y[5], forged.D),
                  "NEGATIVE: forged DLEQ rejected (s != f(5))");
            std::vector<vss::CheckedShare> with_forged = cs;
            with_forged[4] = forged;
            G2 Dno3{};
            check(!vss::agg_dec_share_checked(Dno3, with_forged, T, R),
                  "NEGATIVE: forged share blocks checked aggregation");
            // blame scan names member 5
            std::vector<std::uint64_t> bad_members;
            std::vector<m2::Dleq> proofs;
            std::vector<G2> Ys;
            std::vector<std::pair<std::uint64_t, G2>> shpairs;
            for (auto& c : with_forged) {
                proofs.push_back(c.proof); Ys.push_back(T.Y[c.j]);
                shpairs.push_back(std::make_pair(c.j, c.D));
            }
            m2::blame_scan(bad_members, shpairs, proofs, Ys, R);
            check(bad_members.size() == 1 && bad_members[0] == 5,
                  "blame scan singles out the misbehaving member (5)");
        }
    }

    std::printf("\n%s (fail=%d)\n", fail == 0 ? "STEP63 SCALE-224: ALL PASS" : "STEP63 FAILURES", fail);
    return fail == 0 ? 0 : 1;
}

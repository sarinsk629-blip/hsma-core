// probe: isolate the head-0 full-path failure
#include <hsma/pouw/attention.hpp>
#include <hsma/pouw/logup_ref.hpp>
#include <cstdio>
#include <vector>
using namespace hsma;
int main() {
    const unsigned seq = 4, dm = 8, heads = 2, dh = 4;
    const auto T = pouw::logup::build_all();
    std::vector<fp::fe> X((std::size_t)seq * dm), Wq((std::size_t)dm * dm),
        Wk((std::size_t)dm * dm), Wv((std::size_t)dm * dm), Wo((std::size_t)dm * dm);
    auto fill = [](std::vector<fp::fe>& M, std::uint64_t seed) {
        std::uint64_t st = seed;
        for (std::size_t k = 0; k < M.size(); ++k) {
            st ^= st << 13; st ^= st >> 7; st ^= st << 17;
            M[k] = fp::fe_from_u64((st * 0x9E3779B97F4A7C15ull) % 64ull + 1);
        }
    };
    fill(X, 0x4174746Eull); fill(Wq, 0x5711ull); fill(Wk, 0x5722ull);
    fill(Wv, 0x5733ull); fill(Wo, 0x5744ull);

    std::vector<fp::fe> Qm, Km, Vm;
    pouw::attn::matmul(X, Wq, Qm, seq, dm, dm);
    pouw::attn::matmul(X, Wk, Km, seq, dm, dm);
    pouw::attn::matmul(X, Wv, Vm, seq, dm, dm);
    pouw::attn::descale7(Qm); pouw::attn::descale7(Km); pouw::attn::descale7(Vm);

    // head 0 pieces
    std::vector<fp::fe> Qh, Kh, Vh, KhT, Sh;
    pouw::attn::col_slice(Qm, seq, dm, 0, dh, Qh);
    pouw::attn::col_slice(Km, seq, dm, 0, dh, Kh);
    pouw::attn::col_slice(Vm, seq, dm, 0, dh, Vh);
    pouw::attn::transpose(Kh, seq, dh, KhT);
    pouw::attn::matmul(Qh, KhT, Sh, seq, seq, dh);

    pouw::softmax::SoftmaxBatch sm(900);
    const auto R = pouw::softmax::softmax_rows(Sh, seq, T, &sm);
    std::printf("R.ok=%d bad=%zu denom_rows:\n", (int)R.ok, R.bad_entry);
    for (unsigned r = 0; r < seq; ++r) {
        int psum = 0;
        for (unsigned j = 0; j < seq; ++j) psum += R.P[r * seq + j];
        std::printf("  row %u psum=%d P: ", r, psum);
        for (unsigned j = 0; j < seq; ++j) std::printf("%d ", R.P[r * seq + j]);
        std::printf("\n");
    }
    const auto te = pouw::logup::table_side_sum(sm.exp,
        [&](unsigned i){ return pouw::softmax::exp_at(T, i); });
    const auto tr = pouw::logup::table_side_sum(sm.rcp,
        [&](unsigned i){ return pouw::softmax::rcp_at(T, i); });
    std::printf("exp balanced=%d rcp balanced=%d\n",
        (int)pouw::logup::balanced(sm.exp, te), (int)pouw::logup::balanced(sm.rcp, tr));

    // prove the S leg and A leg standalone, verify standalone
    const auto SP = pouw::prove_gemm_v2(Qh, KhT, Sh, seq, seq, dh);
    std::printf("S leg verify: %d\n", (int)pouw::verify_gemm_v2(SP, Qh, KhT, Sh));
    std::vector<fp::fe> Pfe((std::size_t)seq * seq), Ah((std::size_t)seq * dh);
    for (std::size_t k = 0; k < Pfe.size(); ++k)
        Pfe[k] = fp::fe_from_u64((std::uint64_t)R.P[k]);
    pouw::attn::matmul(Pfe, Vh, Ah, seq, seq, dh);
    const auto AP = pouw::prove_gemm_v2(Pfe, Vh, Ah, seq, dh, seq);
    std::printf("A leg verify: %d\n", (int)pouw::verify_gemm_v2(AP, Pfe, Vh, Ah));
    return 0;
}

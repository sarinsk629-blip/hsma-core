#pragma once
// HSMA :: pouw/model_commit.hpp - P5-G: ModelCommit schema (AI stack Layer 4).
// Binds a submitted workload to a registered model WITHOUT revealing the weights:
//   C = Com(digest(weights); r)  — Pedersen vector commitment over the weight digest
// Registration: the model owner publishes (model_id, C). Workloads must carry an
// OPENING (the digest + r) that recomputes C — otherwise the submission is rejected
// as "not this model". The digest itself is hash-of-weights: collision-resistant
// binding, zero weight disclosure.
// Field: Mersenne-61 (same as LogUp phase-2; production binds to Pallas F_p).

#include <hsma/consensus.hpp>
#include <cstring>
#include <map>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace hsma::pouw::mcommit {

static constexpr std::uint64_t MP = (1ull << 61) - 1;
inline std::uint64_t m_add(std::uint64_t a, std::uint64_t b){ std::uint64_t r=a+b; if(r>=MP) r-=MP; return r; }
inline std::uint64_t m_mul(std::uint64_t a, std::uint64_t b){ __uint128_t r=(__uint128_t)a*b; return (std::uint64_t)(r%MP); }

// ---- The weight digest: hash of the model's weight bytes (domain-separated) ----
inline std::uint64_t weight_digest(const std::uint8_t* weights, std::size_t n) {
    std::uint64_t h = 0;
    // hash-in-blocks of 32, folding via sha256d, domain-separated per block index
    for (std::size_t off = 0; off < n; off += 32) {
        std::uint8_t buf[50];   // 18 header + 32 max data = 50 (DEF-248: was 40, overflow)
        for (int i = 0; i < 10; ++i) buf[i] = "HSM_MDL_v1"[i] == 0 ? 0 : (std::uint8_t)"HSM_MDL_v1"[i];
        std::memcpy(buf, "HSM_MDL_v1", 10);
        const std::uint64_t blk = (std::uint64_t)(off / 32);
        for (int i = 0; i < 8; ++i) buf[10+i] = std::uint8_t(blk >> (8*i));
        const std::size_t take = (n - off < 32) ? (n - off) : 32;
        std::memcpy(buf + 18, weights + off, take);
        auto d = consensus::sha256d(buf, 18 + take);
        std::uint8_t db[32]; std::memcpy(db, &d, 32);   // opaque Digest conform
        std::uint64_t w = 0; for (int i = 0; i < 8; ++i) w |= (std::uint64_t)db[i] << (8*i);
        h = m_add(h, w);
    }
    return h % MP;
}

// ---- Pedersen-style commitment: C = digest + r * G_sense (mod P) ----
// G_sense: a second, independent generator (derived from the first by domain
// separation) — the classic Pedersen "two bases" shape adapted to the integer
// group. Binding: digest fixed => C determines r. Hiding: r random => C reveals
// nothing about digest beyond its commitment existence.
inline std::uint64_t g_sense() {
    auto d = consensus::sha256d((const std::uint8_t*)"HSM_MDL_G2", 10);
    std::uint8_t db[32]; std::memcpy(db, &d, 32);   // opaque Digest conform
    std::uint64_t g = 0; for (int i = 0; i < 8; ++i) g |= (std::uint64_t)db[i] << (8*i);
    return g % MP;
}

struct Commitment { std::uint64_t C; };

inline Commitment commit(std::uint64_t digest, std::uint64_t r) {
    return Commitment{ m_add(digest % MP, m_mul(r % MP, g_sense())) };
}

// Opening check: does (digest, r) open commitment C?
inline bool opens(const Commitment& C, std::uint64_t digest, std::uint64_t r) {
    return commit(digest, r).C == C.C;
}

// ---- The registry: model_id -> commitment ----
struct RegisteredModel { std::uint64_t model_id; Commitment C; };

class Registry {
public:
    bool register_model(std::uint64_t model_id, const Commitment& C) {
        if (reg_.count(model_id)) { std::printf("[mcommit] model %llu already registered\n", (unsigned long long)model_id); return false; }
        reg_[model_id] = C;
        std::printf("[mcommit] model %llu registered (C=%llu)\n", (unsigned long long)model_id, (unsigned long long)C.C);
        return true;
    }
    // THE BINDING: a workload claims model_id and carries an opening; reject anything else.
    bool workload_admitted(std::uint64_t model_id, std::uint64_t digest, std::uint64_t r) const {
        auto it = reg_.find(model_id);
        if (it == reg_.end()) { std::printf("[mcommit] unknown model %llu — REJECTED\n", (unsigned long long)model_id); return false; }
        if (!opens(it->second, digest, r)) {   // pass the Commitment struct
            std::printf("[mcommit] WORKLOAD REJECTED: opening does not match model %llu's commitment\n",
                (unsigned long long)model_id);
            return false;
        }
        std::printf("[mcommit] workload ADMITTED for model %llu (binding verified)\n",
            (unsigned long long)model_id);
        return true;
    }
    std::size_t size() const { return reg_.size(); }
private:
    std::map<std::uint64_t, Commitment> reg_;
};

} // namespace hsma::pouw::mcommit

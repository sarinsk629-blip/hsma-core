#pragma once
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <unordered_map>
#include <vector>
#include <hsma/tx.hpp>

namespace hsma::mempool {

class Mempool {
public:
    void push(const Transaction& tx) { queue_.push_back(tx); }
    bool empty() const noexcept { return queue_.empty(); }
    std::size_t size() const noexcept { return queue_.size(); }

    static bool tx_less(const Transaction& a, const Transaction& b) noexcept {
        const auto ka = fp::fe_to_canonical(a.sender_key);
        const auto kb = fp::fe_to_canonical(b.sender_key);
        for (int i = 3; i >= 0; --i)
            if (ka.l[i] != kb.l[i]) return ka.l[i] < kb.l[i];
        if (a.nonce != b.nonce)         return a.nonce < b.nonce;
        const auto ra = fp::fe_to_canonical(a.recipient_key);
        const auto rb = fp::fe_to_canonical(b.recipient_key);
        for (int i = 3; i >= 0; --i)
            if (ra.l[i] != rb.l[i]) return ra.l[i] < rb.l[i];
        if (a.amount != b.amount)       return a.amount < b.amount;
        return a.fee < b.fee;
    }

    void sort_deterministic() { std::sort(queue_.begin(), queue_.end(), tx_less); }

    smt::Handle execute_batch(smt::Vault& vault, smt::Handle current_root,
                              std::vector<Transaction>& executed_out,
                              std::vector<TxError>&     status_out) {
        sort_deterministic();
        executed_out.reserve(queue_.size());
        status_out.reserve(queue_.size());

        smt::Updater updater(vault);
        smt::Handle root = current_root;

        for (const auto& tx : queue_) {
            smt::AccountState s{}, r{};
            const bool sf = lookup_account(vault, root, tx.sender_key, s);
            const bool rf = lookup_account(vault, root, tx.recipient_key, r);
            const bool self = same_key(tx.sender_key, tx.recipient_key);

            smt::AccountState s_new{}, r_new{};
            const RuleInput in{s, sf, rf, r, self};
            const TxError verdict = apply_rules(tx, in, &s_new, &r_new);
            if (verdict != TxError::OK) { status_out.push_back(verdict); continue; }

            auto rs = updater.set_account(root, tx.sender_key, s_new);
            if (rs.stats.fault) { status_out.push_back(TxError::MALFORMED); continue; }
            root = rs.new_root;

            if (!self) {
                auto rr = updater.set_account(root, tx.recipient_key, r_new);
                if (rr.stats.fault) { status_out.push_back(TxError::MALFORMED); continue; }
                root = rr.new_root;
            }
            executed_out.push_back(tx);
            status_out.push_back(TxError::OK);
        }
        queue_.clear();
        return root;
    }

private:
    std::vector<Transaction> queue_;
};

} // namespace hsma::mempool

// ── P3 production (Zero-MEV): the encrypted-envelope store ──────────────────
// The conformance surface for the node's mempool semantics at production
// volume: O(1) content-addressed dedup (DEF-P3-03), the beacon ordering
// ceremony over ALL entries (DEF-P3-04), and the O(1)-message late-joiner
// sync batch (DEF-P3-08). Wire record: eix(4) || member(8) || D_j(192).
#include <hsma/m2envelope.hpp>

namespace hsma::mempool {

struct CthKey {
    std::uint8_t b[32];
    bool operator==(const CthKey& o) const { return std::memcmp(b, o.b, 32) == 0; }
};
struct CthHash {
    std::size_t operator()(const CthKey& k) const {   // FNV-1a over the content hash
        std::size_t h = 1469598103934665603ull;
        for (int i = 0; i < 32; ++i) { h ^= k.b[i]; h *= 1099511628211ull; }
        return h;
    }
};

class EnvelopeStore {
public:
    // O(1) content-addressed insert; false when the cth already exists
    // (a repeated envelope IS the same envelope — DEF-241 semantics kept).
    bool push(const m2env::Envelope& env, std::size_t* pos_out = nullptr) {
        CthKey ck{};
        std::memcpy(ck.b, env.cth, 32);
        if (idx_.count(ck)) return false;
        const std::size_t pos = pool_.size();
        idx_.emplace(ck, pos);
        pool_.push_back(env);
        if (pos_out) *pos_out = pos;
        return true;
    }
    bool contains(const std::uint8_t cth[32]) const {
        CthKey ck{}; std::memcpy(ck.b, cth, 32);
        return idx_.count(ck) != 0;
    }
    std::size_t size() const noexcept { return pool_.size(); }
    const m2env::Envelope& at(std::size_t i) const { return pool_[i]; }

    // The ordering ceremony: sort keys = sort_key(beacon, cth) for EVERY entry
    // (DEF-P3-04: no partial fills), canonical order = key ascending,
    // commitment root = order_root over the sorted cths.
    bool ordered_root(std::uint8_t out[32], const std::uint8_t beacon[32]) const {
        const std::size_t n = pool_.size();
        if (n == 0) return false;
        std::vector<std::array<std::uint8_t, 32>> sks(n);
        for (std::size_t i = 0; i < n; ++i)
            threshold::m2::sort_key(sks[i].data(), beacon, pool_[i].cth);
        std::vector<std::size_t> order(n);
        for (std::size_t i = 0; i < n; ++i) order[i] = i;
        std::sort(order.begin(), order.end(),
                  [&](std::size_t a, std::size_t b) {
                      return std::memcmp(sks[a].data(), sks[b].data(), 32) < 0;
                  });
        std::vector<std::array<std::uint8_t, 32>> sorted(n);
        for (std::size_t i = 0; i < n; ++i)
            std::memcpy(sorted[i].data(), pool_[order[i]].cth, 32);
        threshold::m2::order_root(out,
            reinterpret_cast<const std::uint8_t (*)[32]>(sorted.data()), n);
        return true;
    }

    // Late-joiner sync (DEF-P3-08): the full share set in ONE payload.
    // Record: eix(u32 LE) || member(u64 LE) || D_j(192B) = 204 bytes.
    void sync_batch_encode(std::uint64_t member,
                           const std::vector<std::pair<std::uint64_t, std::vector<std::uint8_t>>>& shares,
                           std::vector<std::uint8_t>& out) const {
        out.clear();
        const std::uint32_t cnt = (std::uint32_t)shares.size();
        for (int i = 0; i < 4; ++i) out.push_back(std::uint8_t(cnt >> (8*i)));   // LE (wire law)
        for (const auto& [eix, ser] : shares) {
            for (int i = 0; i < 4; ++i) out.push_back(std::uint8_t(eix >> (8*i)));   // LE
            for (int i = 0; i < 8; ++i) out.push_back(std::uint8_t(member >> (8*i)));  // LE
            out.insert(out.end(), ser.begin(), ser.begin() + 192);
        }
    }
    static bool sync_batch_decode(const std::vector<std::uint8_t>& payload,
                                  std::vector<std::pair<std::uint32_t, std::vector<std::uint8_t>>>& out,
                                  std::uint64_t* member_out = nullptr) {
        out.clear();
        if (payload.size() < 4 || (payload.size() - 4) % 204 != 0) return false;
        const std::uint32_t cnt = (std::uint32_t)payload[0] | ((std::uint32_t)payload[1] << 8)
            | ((std::uint32_t)payload[2] << 16) | ((std::uint32_t)payload[3] << 24);
        if (cnt != (payload.size() - 4) / 204) return false;
        if (member_out) {
            std::uint64_t m = 0;
            // the member is a PER-RECORD field at record offset 4 — read the
            // first record's member (batch law: one sender per batch)
            for (int i = 0; i < 8; ++i) m |= (std::uint64_t)payload[8 + i] << (8*i);
            *member_out = m;
        }
        out.reserve(cnt);
        for (std::uint32_t r = 0; r < cnt; ++r) {
            const std::uint8_t* p = payload.data() + 4 + r * 204;
            const std::uint32_t eix = (std::uint32_t)p[0] | ((std::uint32_t)p[1] << 8)
                | ((std::uint32_t)p[2] << 16) | ((std::uint32_t)p[3] << 24);
            out.push_back({eix, std::vector<std::uint8_t>(p + 12, p + 12 + 192)});
        }
        return true;
    }

private:
    std::vector<m2env::Envelope> pool_;
    std::unordered_map<CthKey, std::size_t, CthHash> idx_;
};

} // namespace hsma::mempool

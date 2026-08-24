#pragma once
#include <algorithm>
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

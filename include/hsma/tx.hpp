// ═══════════════════════════════════════════════════════════════════════════
//  HSMA :: tx.hpp — transaction model, introspection, validation gate
//  DEC-119 money math (boundedness-proven delta) · DEC-121/123 read binding
// ═══════════════════════════════════════════════════════════════════════════
#pragma once
#include <cstring>
#include <hsma/params.hpp>
#include <hsma/fe.hpp>
#include <hsma/update.hpp>

namespace hsma::mempool {

inline constexpr unsigned __int128 BAL_MAX =
    (((unsigned __int128)1) << params::STATE_WIDTH_BITS) - 1;   // 2^126 − 1

struct Transaction {
    fp::fe sender_key;
    fp::fe recipient_key;
    unsigned __int128 amount;
    unsigned __int128 fee;
    std::uint64_t nonce;
};

enum class TxError : int {
    OK = 0, SENDER_NOT_FOUND, INSUFFICIENT_BALANCE,
    INVALID_NONCE, COST_OVERFLOW, CREDIT_OVERFLOW, MALFORMED
};

inline bool same_key(const fp::fe& a, const fp::fe& b) noexcept {
    return fp::fe_to_canonical(a) == fp::fe_to_canonical(b);
}

inline bool lookup_account(const smt::Vault& vault, smt::Handle root,
                           const fp::fe& key, smt::AccountState& out_st) noexcept {
    const std::uint64_t idx = smt::index_of(key);
    smt::Handle cur = root;
    for (int lvl = int(params::SMT_DEPTH) - 1; lvl >= 0; --lvl) {
        if (cur == smt::HEMPTY) return false;
        const smt::Entry* e = vault.deref(cur);
        if (!e || e->tag != std::uint8_t(smt::Tag::MID)) return false;
        cur = ((idx >> lvl) & 1) ? e->w[1] : e->w[0];
    }
    if (cur == smt::HEMPTY) return false;
    const smt::Entry* tl = vault.deref(cur);
    if (!tl || tl->tag != std::uint8_t(smt::Tag::TLEAF)) return false;
    const smt::Entry* rec = vault.deref(tl->w[0]);
    if (!rec || rec->tag != std::uint8_t(smt::Tag::REC)) return false;

    fp::fe stored_key{};
    std::memcpy(stored_key.l.data(), rec->w, 32);
    if (!(stored_key == fp::fe_to_canonical(key))) return false;   // DEC-121/123

    std::byte buf[32]{};                                // bytes 24..31 remain 0
    std::memcpy(buf, rec->w + 4, 24);                   // full schema window
    const auto dec = fp::fe_from_le_bytes(buf);
    if (!dec.ok) return false;
    out_st = smt::unpack_payload(dec.value);
    return true;
}

struct RuleInput {
    smt::AccountState sender;
    bool              sender_found;
    bool              recipient_found;
    smt::AccountState recipient;
    bool              self_transfer;
};

inline TxError apply_rules(const Transaction& tx, const RuleInput& in,
                           smt::AccountState* sender_out,
                           smt::AccountState* recipient_out) noexcept {
    if (!in.sender_found)                 return TxError::SENDER_NOT_FOUND;
    if (tx.nonce != in.sender.nonce + 1)  return TxError::INVALID_NONCE;

    unsigned __int128 cost;
    if (__builtin_add_overflow(tx.amount, tx.fee, &cost))
                                          return TxError::COST_OVERFLOW;
    if (in.sender.bal_sign || in.sender.bal_mag < cost)
                                          return TxError::INSUFFICIENT_BALANCE;

    // sender_new = bal − cost + net_return ∈ [bal−cost, bal] ⊆ [0, 2^126):
    // overflow-impossible and mint-impossible by solvency (net_return ≤ cost).
    const unsigned __int128 net_return = in.self_transfer ? tx.amount : 0;
    const unsigned __int128 sender_new = in.sender.bal_mag - cost + net_return;

    if (!in.self_transfer && in.recipient_found) {
        unsigned __int128 sum;
        if (__builtin_add_overflow(in.recipient.bal_mag, tx.amount, &sum) ||
            sum > BAL_MAX)                          return TxError::CREDIT_OVERFLOW;
        if (recipient_out) {
            recipient_out->bal_mag  = sum;
            recipient_out->nonce    = in.recipient.nonce;   // credits burn no nonce
            recipient_out->bal_sign = false;
            recipient_out->flags    = in.recipient.flags;
        }
    } else if (!in.self_transfer && !in.recipient_found) {
        if (tx.amount > BAL_MAX)                    return TxError::CREDIT_OVERFLOW;
        if (recipient_out) *recipient_out = smt::AccountState{tx.amount, false, 0, 0};
    }

    if (sender_out) {
        sender_out->bal_mag  = sender_new;
        sender_out->bal_sign = false;
        sender_out->nonce    = in.sender.nonce + 1;
        sender_out->flags    = in.sender.flags;
    }
    return TxError::OK;
}

inline TxError validate_transaction(const Transaction& tx,
                                    const smt::Vault& vault, smt::Handle root) {
    smt::AccountState s{}, r{};
    const bool sf = lookup_account(vault, root, tx.sender_key, s);
    const bool rf = lookup_account(vault, root, tx.recipient_key, r);
    const RuleInput in{s, sf, rf, r, same_key(tx.sender_key, tx.recipient_key)};
    return apply_rules(tx, in, nullptr, nullptr);
}

} // namespace hsma::mempool

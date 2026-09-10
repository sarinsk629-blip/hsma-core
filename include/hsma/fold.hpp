// HSMA :: fold.hpp — the fold step family (Step 14, DEC-207).
// F_head/F_exec/F_close over the existing mempool semantics (apply_rules,
// Step 5, DEC-119/121/123). The digest chain runs on HSM_FOLD_v1 (registry);
// the pt-binding on HSM_PT_v1. PAD = total neutrality (state + digest).
// DEC-127; DEC-090; PC enforcement at the API level.
#pragma once
#include <hsma/tx.hpp>
#include <hsma/update.hpp>
#include <hsma/poseidon.hpp>
#include <vector>

namespace hsma::fold {

enum class Status : std::uint8_t { EXEC = 0, SKIP_USER = 1, PAD = 2 };
enum class Verdict : std::uint8_t {
    OK_EXEC = 0, OK_SKIP = 1, PAD_NEUTRAL = 2,
    REJECT_BINDING = 3, REJECT_NONCE = 4, REJECT_INSOLVENT = 5,
    REJECT_PC = 6
};

struct DecreeEntry {
    fp::fe sender_key, recipient_key, pt_hash;
    unsigned __int128 amount, fee;
    std::uint64_t nonce;
    Status status;
};

struct FoldState {
    smt::Handle state_root;
    fp::fe digest;
};

// u128 -> fe (canonical limbs, high limbs zero)
inline fp::fe u128_to_fe(unsigned __int128 v) {
    std::array<std::uint64_t, 4> c{};
    c[0] = static_cast<std::uint64_t>(v);
    c[1] = static_cast<std::uint64_t>(v >> 64);
    return fp::fe_from_canonical_limbs(c);
}

// pt encoding: e1 = fe(amount), e2 = fe(fee*2^64 + nonce)
inline fp::fe pt_hash_of(unsigned __int128 amount, unsigned __int128 fee,
                         std::uint64_t nonce) {
    const fp::fe e1 = u128_to_fe(amount);
    const fp::fe e2 = u128_to_fe((fee << 64) | nonce);
    return poseidon3(dom::Dom::HSM_PT_v1, e1, e2);
}

// F_head: digest <- P3(HSM_FOLD_v1, prev_digest, decree_root)
inline fp::fe f_head(const fp::fe& prev_digest, const fp::fe& decree_root) {
    return poseidon3(dom::Dom::HSM_FOLD_v1, prev_digest, decree_root);
}

// F_close: digest <- P3(HSM_FOLD_v1, digest, count)
inline fp::fe f_close(const fp::fe& digest, std::uint64_t count) {
    return poseidon3(dom::Dom::HSM_FOLD_v1, digest, fp::fe_from_u64(count));
}

// F_exec: the gates + the existing apply_rules + set_account + digest update
inline Verdict f_exec(smt::Vault& vault, FoldState& fs, const DecreeEntry& e) {
    if (e.status == Status::PAD) return Verdict::PAD_NEUTRAL;

    // binding gate: Poseidon(HSM_PT_v1, pt) == pt_hash
    const fp::fe computed = pt_hash_of(e.amount, e.fee, e.nonce);
    if (!(fp::fe_to_canonical(computed) == fp::fe_to_canonical(e.pt_hash)))
        return Verdict::REJECT_BINDING;

    // nonce gate (via the SMT read — key-bound per DEC-121/123)
    smt::AccountState s{};
    if (!mempool::lookup_account(vault, fs.state_root, e.sender_key, s))
        return Verdict::REJECT_NONCE;
    if (e.nonce != s.nonce + 1)
        return Verdict::REJECT_NONCE;

    // solvency / LT gate (DEC-032)
    unsigned __int128 cost;
    if (__builtin_add_overflow(e.amount, e.fee, &cost))
        return Verdict::REJECT_INSOLVENT;
    if (s.bal_sign || s.bal_mag < cost) {
        if (e.status == Status::SKIP_USER) {
            // SKIP_USER: 25% burn, no nonce consumption
            unsigned __int128 burn = (e.fee * 25) / 100;
            s.bal_mag -= (burn < s.bal_mag) ? burn : s.bal_mag;
            s.bal_sign = false;
            smt::Updater updater(vault);
            auto rs = updater.set_account(fs.state_root, e.sender_key, s);
            if (rs.stats.fault) return Verdict::REJECT_INSOLVENT;
            fs.state_root = rs.new_root;
            fs.digest = poseidon3(dom::Dom::HSM_FOLD_v1, fs.digest, e.pt_hash);
            return Verdict::OK_SKIP;
        }
        return Verdict::REJECT_INSOLVENT;
    }

    // EXEC: the existing apply_rules semantics (Step 5, verbatim)
    smt::AccountState r{};
    const bool rf = mempool::lookup_account(vault, fs.state_root, e.recipient_key, r);
    const bool self = mempool::same_key(e.sender_key, e.recipient_key);
    const mempool::Transaction tx{e.sender_key, e.recipient_key, e.amount, e.fee, e.nonce};
    const mempool::RuleInput in{s, true, rf, r, self};
    smt::AccountState s_new{}, r_new{};
    if (mempool::apply_rules(tx, in, &s_new, &r_new) != mempool::TxError::OK)
        return Verdict::REJECT_INSOLVENT;

    smt::Updater updater(vault);
    auto rs = updater.set_account(fs.state_root, e.sender_key, s_new);
    if (rs.stats.fault) return Verdict::REJECT_INSOLVENT;
    fs.state_root = rs.new_root;
    if (!self) {
        auto rr = updater.set_account(fs.state_root, e.recipient_key, r_new);
        if (rr.stats.fault) return Verdict::REJECT_INSOLVENT;
        fs.state_root = rr.new_root;
    }
    fs.digest = poseidon3(dom::Dom::HSM_FOLD_v1, fs.digest, e.pt_hash);
    return Verdict::OK_EXEC;
}

} // namespace hsma::fold

#pragma once
// HSMA :: econ/stake.hpp - P5-E: the economic enforcement layer.
// Closes PROPERTY_REGISTER waivers: Slashing, Anti-Sybil, Adversarial Bound.
// Testnet scope: stake units are ledger entries (no token). Token binding later
// is a parameter change (the registered community-governance decision).
// Integer-only throughout (DEC-090).

#include <hsma/consensus.hpp>
#include <cstdio>
#include <map>
#include <vector>

namespace hsma::econ {

struct Params {
    std::uint64_t min_bond = 50000;
    std::uint64_t activation_lag = 2;         // E+2
    std::uint64_t unbonding_epochs = 21;
    std::uint64_t evidence_horizon = 14;
    std::uint64_t max_adversarial_bp = 2000;  // f < 0.20 (basis points)
    std::uint64_t cluster_cap = 100000;  // DEF-245: was 100 — scale-inconsistent with B_min 50,000; the whitepaper cap is 100,000 units
    std::uint64_t max_total_weight = 1000000;
};

enum class BondState : std::uint8_t { BONDING, ACTIVE, UNBONDING, SLASHED, WITHDRAWN };

struct Bond {
    std::uint64_t member_id{};
    std::uint64_t amount{};
    std::uint64_t deposit_epoch{};
    std::uint64_t unbond_epoch{};
    BondState state = BondState::BONDING;
    std::uint64_t cluster = 0;
};

class StakeRegistry {
public:
    explicit StakeRegistry(const Params& p) : P_(p) {}

    bool deposit(std::uint64_t member, std::uint64_t amount, std::uint64_t epoch,
                 std::uint64_t cluster) {
        if (amount < P_.min_bond) {
            std::fprintf(stderr, "[stake] deposit REJECTED: %llu < B_min %llu\n",
                (unsigned long long)amount, (unsigned long long)P_.min_bond);
            return false;
        }
        bonds_[member].push_back(Bond{member, amount, epoch, 0, BondState::BONDING, cluster});
        return true;
    }

    void tick_epoch(std::uint64_t epoch) {
        for (auto& [member, vec] : bonds_)
            for (auto& b : vec) {
                if (b.state == BondState::BONDING && epoch >= b.deposit_epoch + P_.activation_lag)
                    b.state = BondState::ACTIVE;                    // E+2 law
                if (b.state == BondState::UNBONDING && epoch >= b.unbond_epoch + P_.unbonding_epochs)
                    b.state = BondState::WITHDRAWN;
            }
    }

    bool request_unbond(std::uint64_t member, std::uint64_t epoch) {
        bool any = false;
        for (auto& b : bonds_[member])
            if (b.state == BondState::ACTIVE) { b.state = BondState::UNBONDING; b.unbond_epoch = epoch; any = true; }
        return any;
    }

    std::uint64_t slash_equivocation(std::uint64_t member) {
        std::uint64_t burned = 0;
        for (auto& b : bonds_[member])
            if (b.state == BondState::ACTIVE || b.state == BondState::UNBONDING ||
                b.state == BondState::BONDING) { burned += b.amount; b.amount = 0; b.state = BondState::SLASHED; }
        std::printf("[stake] SLASHED member %llu: %llu burned (100 pct, equivocation)\n",
            (unsigned long long)member, (unsigned long long)burned);
        return burned;
    }

    std::uint64_t active_weight(std::uint64_t member) const {
        std::uint64_t w = 0;
        auto it = bonds_.find(member);
        if (it == bonds_.end()) return 0;
        for (const auto& b : it->second) if (b.state == BondState::ACTIVE) w += b.amount;
        return w;
    }

    std::uint64_t cluster_capped_weight(std::uint64_t member) const {
        const std::uint64_t raw = active_weight(member);
        auto it = clusters_.find(cluster_of(member));
        const std::uint64_t cluster_total = (it == clusters_.end()) ? raw : it->second;
        if (cluster_total <= P_.cluster_cap) return raw;
        if (cluster_total == 0) return 0;
        return (raw * P_.cluster_cap) / cluster_total;
    }

    void set_cluster_total(std::uint64_t cluster, std::uint64_t total) { clusters_[cluster] = total; }
    std::uint64_t cluster_of(std::uint64_t member) const {
        auto it = bonds_.find(member);
        return (it == bonds_.end() || it->second.empty()) ? 0 : it->second.front().cluster;
    }

    enum class AdversarialVerdict : std::uint8_t { SAFE, HALT };
    AdversarialVerdict adversarial_check(std::uint64_t total_active_weight,
                                         std::uint64_t adversarial_active_weight) const {
        if (total_active_weight == 0) return AdversarialVerdict::SAFE;
        const std::uint64_t f_bp = (adversarial_active_weight * 10000) / total_active_weight;
        if (f_bp >= P_.max_adversarial_bp) {
            std::fprintf(stderr, "[stake] ADVERSARIAL BOUND BREACH: f=%llu.%02llu pct >= 20 pct - HALT\n",
                (unsigned long long)(f_bp / 100), (unsigned long long)(f_bp % 100));
            return AdversarialVerdict::HALT;
        }
        return AdversarialVerdict::SAFE;
    }

    std::uint64_t total_active() const {
        std::uint64_t t = 0;
        for (const auto& [m, vec] : bonds_) for (const auto& b : vec)
            if (b.state == BondState::ACTIVE) t += b.amount;
        return t;
    }

    // observation helper (conformance tests): primary bond's state
    BondState primary_state(std::uint64_t member) const {
        auto it = bonds_.find(member);
        return (it == bonds_.end() || it->second.empty()) ? BondState::BONDING : it->second.front().state;
    }

    const Params& params() const { return P_; }

private:
    Params P_;
    std::map<std::uint64_t, std::vector<Bond>> bonds_;
    std::map<std::uint64_t, std::uint64_t> clusters_;
};

} // namespace hsma::econ

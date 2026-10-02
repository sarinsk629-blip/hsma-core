#include <hsma/econ/stake.hpp>
// P5-E golden constants — INLINED from the Python oracle (scripts/gen/steps/step35.py)
// Bilingual law intact: these values are oracle-computed; the C++ must reproduce them.
// (the generated/stake_golden.hpp remains for tooling; the test embeds to be path-independent)
namespace econ_golden {
inline constexpr long long ACTIVATE_E2[] = {5,6,7};
inline constexpr int ACTIVATE_E2_STATES[] = {0,0,1};
inline constexpr long long BMIN = 50000, BMIN_REJ = 49999;
inline constexpr long long SLASH_BONDS[] = {150000,100000,50000}; // >= B_min
inline constexpr long long SLASH_BURNED = 300000; inline constexpr int SLASH_STATE = 3;
inline constexpr long long CC_RAW = 80000, CC_TOTAL = 150000, CC_CAP = 100000;
inline constexpr long long CC_EXPECT = 53333;
inline constexpr long long ADV_SAFE = 199999, ADV_TOTAL = 1000000, ADV_HALT = 200000;
inline constexpr long long UNB_E = 10, UNB_W = 21;
inline constexpr int UNB_STATES[] = {2,2,4};
}
using namespace econ_golden;
#include <cstdio>
using namespace hsma;
using econ::BondState;
static const char* BS(BondState s){ switch(s){case BondState::BONDING:return"BONDING";case BondState::ACTIVE:return"ACTIVE";case BondState::UNBONDING:return"UNBONDING";case BondState::SLASHED:return"SLASHED";default:return"WITHDRAWN";} }
int main(){
    int fails = 0; auto C = [&](bool ok, const char* w){ if(!ok){ std::printf("FAIL: %s\n", w); ++fails; } };
    econ::Params P{}; econ::StakeRegistry R(P);

    // V1: E+2 activation
    C(R.deposit(1, 50000, 5, 0), "V1 deposit");
    for (int i = 0; i < 3; ++i) { R.tick_epoch(5 + (unsigned)i);
        C(R.primary_state(1) == (econ::BondState)econ_golden::ACTIVATE_E2_STATES[i], "V1 state"); }
    C(std::string(BS(R.primary_state(1))) == "ACTIVE", "V1 final ACTIVE");

    // V2: B_min
    econ::StakeRegistry R2(P);
    C(!R2.deposit(9, econ_golden::BMIN_REJ, 0, 0), "V2 reject below B_min");
    C(R2.deposit(9, econ_golden::BMIN, 0, 0), "V2 accept at B_min");

    // V3: slash 100%
    econ::StakeRegistry R3(P);
    R3.deposit(7, 150000, 0, 0); R3.deposit(7, 100000, 0, 0); R3.deposit(7, 50000, 0, 0);
    R3.tick_epoch(5); // all ACTIVE
    const auto burned = R3.slash_equivocation(7);
    C(burned == econ_golden::SLASH_BURNED, "V3 burned total");
    C(R3.primary_state(7) == (econ::BondState)econ_golden::SLASH_STATE, "V3 SLASHED");
    C(R3.total_active() == 0, "V3 zero active after slash");

    // V4: cluster cap floor
    {   econ::Params P4{}; econ::StakeRegistry R4(P4);
        R4.set_cluster_total(3, econ_golden::CC_TOTAL);
        R4.deposit(4, econ_golden::CC_RAW, 0, 3); R4.tick_epoch(5);
        const auto capped = R4.cluster_capped_weight(4);
        C(capped == (std::uint64_t)econ_golden::CC_EXPECT, "V4 cluster floor");
    }

    // V5/V6: adversarial bound
    C(R.adversarial_check(econ_golden::ADV_TOTAL, econ_golden::ADV_SAFE) == econ::StakeRegistry::AdversarialVerdict::SAFE, "V5 SAFE");
    C(R.adversarial_check(econ_golden::ADV_TOTAL, econ_golden::ADV_HALT) == econ::StakeRegistry::AdversarialVerdict::HALT, "V6 HALT");

    // V7: unbonding window
    R.deposit(2, 50000, 0, 0); R.tick_epoch(5); R.request_unbond(2, econ_golden::UNB_E);
    const unsigned te_seq[] = {10u, 30u, 31u};
    for (int i = 0; i < 3; ++i) { R.tick_epoch(te_seq[i]);
        C(R.primary_state(2) == (econ::BondState)econ_golden::UNB_STATES[i], "V7 state"); }

    std::printf("%s\n", fails ? "test_step35: FAILED" : "test_step35: ALL PASS (P5-E mechanisms proven)");
    return fails ? 1 : 0;
}

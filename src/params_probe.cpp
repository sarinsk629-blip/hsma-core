// HSMA Step-1 probe: proves the contract compiles and prints its identity.
#include <hsma/params.hpp>
#include <cstdio>

int main() {
    using namespace hsma::params;
    char hex[16]; fingerprint_hex(hex);

    std::printf("HSMA params contract | ABI v%u\n", ABI_VERSION);
    std::printf("fingerprint        : %.16s\n", hex);
    std::printf("consensus          : f=%.2f%% alpha=%.2f%% phi=%.2f%% (bp-internals only)\n",
                F_BP / 100.0, ALPHA_BP / 100.0, PHI_FLOOR_BP / 100.0);
    std::printf("committee          : n=%u active=%u standby=%u t=%u halt@>%u\n",
                N_SHAREHOLDERS, N_ACTIVE, N_STANDBY, T_THRESHOLD, HALT_LINE - 1);
    std::printf("extremality        : m_max=%u | conf.margin=%u halt.margin=%u\n",
                M_MAX_ADVERSARY_IDENTITIES, CONFIDENTIALITY_MARGIN, HALT_MARGIN);
    std::printf("throughput         : theta=%lld entries/s (%lld x %lld / %lld s)\n",
                (long long)THETA_PER_SEC_NOMINAL,
                (long long)EXEC_STEPS_NOMINAL, (long long)MAX_BATCH_ENTRIES,
                (long long)EPOCH_SECONDS);
    std::printf("registry           : %zu domain names, uniqueness proven\n",
                DOM_REGISTRY.size());
    std::printf("golden params      : %s\n",
                GOLDEN_PARAMS_PINNED ? "PINNED" : "AWAITING PHASE-1 SIMULATION");
    // Percentages above are printf cosmetics ONLY — all arithmetic in this
    // codebase remains integer (DEC-090 scopes the ban to the numeric core).
    return 0;
}

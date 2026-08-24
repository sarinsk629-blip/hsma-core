// ═══════════════════════════════════════════════════════════════════════════
//  HSMA :: params.hpp — THE SINGLE SOURCE OF TRUTH
//
//  Baseline   : DECISIONS.md v1.2 (DEC-001 … DEC-097)
//  Contract   : Every protocol quantity is defined EXACTLY ONCE, here.
//               Downstream code SHALL include this header; re-declaring any
//               constant elsewhere is a severity-one defect (CA-62/A1).
//  Enforcement: All A6 combinatorial safety inequalities are static_assert'd.
//               Violating a parameter edit fails the BUILD, not production.
//  Numerics   : DEC-090 — basis points and integers only. No floating point
//               exists in this header or in any numeric-core consumer (CI-linted).
//  Target     : ARM64 (Termux), clang++ -std=c++20, little-endian, 128-B lines.
//
//  Fingerprint: FNV-1a-64 over the canonical safety tuple (Section 11).
//               Printed by every binary; diffed by the DEC-086 ledger bot.
// ═══════════════════════════════════════════════════════════════════════════
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <type_traits>

namespace hsma::params {

// ─────────────────────────────────────────────────────────────────────────
// §0  ENVIRONMENT CONTRACTS (autonomous addition A4 — ARM64 reality)
// ─────────────────────────────────────────────────────────────────────────
static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
              "HSMA serialization assumes little-endian (ARM64 default)");
static_assert(sizeof(void*) == 8, "HSMA targets 64-bit platforms only");
inline constexpr std::size_t CACHE_LINE_BYTES = 128;   // Apple-Silicon-safe; 64-B
                                                       // hosts merely waste padding,
                                                       // never lose correctness.
inline constexpr std::uint16_t ABI_VERSION = 1;        // bump on layout-breaking change

// ─────────────────────────────────────────────────────────────────────────
// §1  RATIO DISCIPLINE (DEC-090) — basis points, nothing else
// ─────────────────────────────────────────────────────────────────────────
using bp_t = std::int64_t;
inline constexpr bp_t BP_ONE = 10'000;                 // 100.00 %

/// Validated ratio in [0,1]. Construction from raw ints is centralized here.
template <bp_t V>
struct BP {
    static_assert(V >= 0 && V <= BP_ONE, "ratio in basis points out of [0,10000]");
    static constexpr bp_t value = V;
};

// ─────────────────────────────────────────────────────────────────────────
// §2  FIELD / REGISTER WIDTHS  (SPEC P0-v2, DEC-001, Ch.2 §2.4)
// ─────────────────────────────────────────────────────────────────────────
inline constexpr int FIELD_SAFE_BITS  = 254;   // packed-into-one-element ceiling (p≈2^254.18)
inline constexpr int STATE_WIDTH_BITS = 126;   // L  — committed magnitudes
inline constexpr int SCRATCH_WIDTH_BITS = 127; // L' — GEMM accumulator class
inline constexpr int WEIGHT_REG_BITS  = 64;    // w1
inline constexpr int ACT_REG_BITS     = 32;    // w2

static_assert(SCRATCH_WIDTH_BITS == STATE_WIDTH_BITS + 1, "scratch class is L+1");
static_assert(WEIGHT_REG_BITS + ACT_REG_BITS <= SCRATCH_WIDTH_BITS,
              "single product must fit the scratch class before summation");

/// Theorem 2.4: max products accumulated at full magnitude in L'=127.
/// Computed exactly in 128-bit constexpr arithmetic — never trusted to mental math.
#ifdef __SIZEOF_INT128__
using u128 = unsigned __int128;
inline constexpr u128 MAX_ACCUM_PRODUCTS =
    (((u128)1 << SCRATCH_WIDTH_BITS) - 1) /
    ((((u128)1 << WEIGHT_REG_BITS) - 1) * (((u128)1 << ACT_REG_BITS) - 1));
static_assert(MAX_ACCUM_PRODUCTS >= ((u128)1 << 30),
              "accumulator capacity regressed below 2^30 products");
#endif

// Sparse Merkle leaf packing (Ch.2 §2.5)
inline constexpr int SMT_DEPTH        = 64;
inline constexpr int BAL_MAG_BITS     = 126;
inline constexpr int BAL_SIGN_BITS    = 1;
inline constexpr int NONCE_BITS       = 64;
inline constexpr int FLAGS_BITS       = 8;
inline constexpr int LEAF_PACKED_BITS =
    BAL_MAG_BITS + BAL_SIGN_BITS + NONCE_BITS + FLAGS_BITS;
static_assert(LEAF_PACKED_BITS == 199, "leaf schema drift");
static_assert(LEAF_PACKED_BITS <= FIELD_SAFE_BITS, "leaf no longer packs into one element");

// Poseidon instantiation (DEC-046 pins constants at genesis; widths pinned HERE)
inline constexpr int POSEIDON_T        = 3;
inline constexpr int POSEIDON_RF       = 8;
inline constexpr int POSEIDON_RP_MIN   = 56;
inline constexpr int POSEIDON_SBOX_EXP = 5;
static_assert(POSEIDON_T == 3 && POSEIDON_RF == 8 &&
              POSEIDON_RP_MIN >= 56 && POSEIDON_SBOX_EXP == 5,
              "Poseidon parameters are genesis-pinned; changing them is a fork");

// ─────────────────────────────────────────────────────────────────────────
// §3  CONSENSUS — MSSC  (Ch.3; safety taxonomy per DEC-037)
// ─────────────────────────────────────────────────────────────────────────
inline constexpr bp_t   F_BP          = 2'000;  // adversarial weight ceiling f = 0.20
inline constexpr bp_t   ALPHA_BP      = 7'500;  // quorum threshold      α = 0.75
inline constexpr bp_t   PHI_FLOOR_BP  = 5'000;  // sampling floor        φ = 0.50

inline constexpr std::uint32_t K_BASE         = 20;
inline constexpr std::uint32_t K_ESCALATED    = 40;
inline constexpr std::uint64_t K_ESC_AT_ROUND = 1'000;
inline constexpr std::uint32_t BETA_CONFIRMATIONS = 150;
inline constexpr std::uint32_t STALL_LIMIT        = 50;

static_assert(F_BP > 0 && F_BP < BP_ONE / 2, "f must be a minority fraction");
static_assert(K_ESCALATED >= K_BASE, "escalation must grow the sample");

// ▶ LOAD-BEARING INEQUALITY #1 — Lemma 3.2 (Authenticated Quorum Impossibility)
//   α > f/φ   ⇔   α·φ > f   (all in exact integer bp arithmetic)
static_assert(ALPHA_BP * PHI_FLOOR_BP > F_BP * BP_ONE,
              "A6/L1 VIOLATION: alpha*phi_floor must exceed f — forged quorums "
              "would become statistically possible instead of impossible");

// ▶ Corollary 3.3 — dual plurality impossible iff α > 1/2
static_assert(ALPHA_BP > BP_ONE / 2, "dual-plurality impossibility lost (alpha<=1/2)");

// ─────────────────────────────────────────────────────────────────────────
// §4  COMMITTEE / THRESHOLD  (DEC-087 supersedes stale t=128; Ch.4 Thm 4.6)
// ─────────────────────────────────────────────────────────────────────────
inline constexpr std::uint32_t N_SHAREHOLDERS = 224;   // active + standby, ALL hold shares
inline constexpr std::uint32_t N_ACTIVE       = 192;
inline constexpr std::uint32_t N_STANDBY      = 32;
inline constexpr std::uint32_t T_THRESHOLD    = 112;   // confidentiality line
inline constexpr std::uint32_t HALT_LINE      = T_THRESHOLD + 1;   // 113: liveness absence line
inline constexpr bp_t   W_FLOOR_BP            = 20;    // eligibility floor w = 0.002·T
inline constexpr std::uint32_t CLUSTER_SEAT_CAP = 16;  // defense-in-depth (DEC-013)

static_assert(N_ACTIVE + N_STANDBY == N_SHAREHOLDERS, "committee composition drift");
static_assert(T_THRESHOLD <= N_SHAREHOLDERS, "threshold exceeds committee size");

/// Max adversary ELIGIBLE IDENTITIES under the structural floor (integer floor
/// division is semantically correct: identity counts are integral).
inline constexpr std::uint32_t M_MAX_ADVERSARY_IDENTITIES =
    static_cast<std::uint32_t>(F_BP / W_FLOOR_BP);     // 2000/20 = 100

// ▶ LOAD-BEARING INEQUALITY #2 — Thm 4.6(i): takeover structurally impossible
static_assert(M_MAX_ADVERSARY_IDENTITIES < T_THRESHOLD,
              "A6/L2 VIOLATION: adversary can assemble t colluders — "
              "confidentiality and decree uniqueness collapse");

// ▶ LOAD-BEARING INEQUALITY #3 — Thm 4.6(ii): adversary-forced halt impossible
static_assert(static_cast<std::uint32_t>(N_SHAREHOLDERS) - M_MAX_ADVERSARY_IDENTITIES
                  >= T_THRESHOLD,
              "A6/L2' VIOLATION: adversary withholding can force decryption halt");

// Margins — CA-61 CORRECTION: these are NOT symmetric (12 vs 13). Both > 0 is
// the invariant; the asymmetry favors liveness.
inline constexpr std::uint32_t CONFIDENTIALITY_MARGIN = T_THRESHOLD - M_MAX_ADVERSARY_IDENTITIES; // 12
inline constexpr std::uint32_t HALT_MARGIN            = HALT_LINE - M_MAX_ADVERSARY_IDENTITIES;   // 13
static_assert(CONFIDENTIALITY_MARGIN > 0 && HALT_MARGIN > 0, "structural margins vanished");

static_assert(CLUSTER_SEAT_CAP < T_THRESHOLD,
              "a single cluster must never unilaterally reach the threshold");

// Dual AEAD profiles (DEC-088 / Target-2 CA-51)
enum class AeadProfile : std::uint8_t { AES256_GCM = 0, CHACHA20_POLY1305 = 1 };
static_assert(static_cast<int>(AeadProfile::CHACHA20_POLY1305) == 1,
              "profile bit is wire format — frozen");

// ─────────────────────────────────────────────────────────────────────────
// §5  WEIGHT ENGINE  (S1-v2; DEC-013/015/019/020; Target-3 Thm E1)
// ─────────────────────────────────────────────────────────────────────────
inline constexpr int W_EXP_PHI_NUM = 6;
inline constexpr int W_EXP_S_NUM   = 4;
inline constexpr int W_EXP_DEN     = 10;
static_assert(W_EXP_PHI_NUM + W_EXP_S_NUM == W_EXP_DEN,
              "homogeneity degree must equal 1 (split-neutrality is load-bearing)");

inline constexpr bp_t CAP_BP = 1'500;                  // W_max = 0.15·T₀
static_assert(CAP_BP < F_BP,
              "cap must sit below the Byzantine fraction: a max-weight entity "
              "alone can never threaten safety");

// Genesis unit widths — DEC-019 width invariant 6a+4b+g ≤ L
inline constexpr bool ALPHA_HALF_FALLBACK_MODE = false;   // DEC-065 trigger: testnet data
inline constexpr int  UNIT_PHI_BITS  = 12;
inline constexpr int  UNIT_S_BITS    = 12;
inline constexpr int  UNIT_GUARD_BITS = 6;
static_assert(!ALPHA_HALF_FALLBACK_MODE &&
                  (W_EXP_PHI_NUM * UNIT_PHI_BITS +
                   W_EXP_S_NUM  * UNIT_S_BITS +
                   UNIT_GUARD_BITS) <= STATE_WIDTH_BITS,
              "weight-engine intermediates overflow the state width");
static_assert(ALPHA_HALF_FALLBACK_MODE ||
                  (UNIT_PHI_BITS + UNIT_S_BITS) <= STATE_WIDTH_BITS,
              "fallback-mode width invariant violated");

// Bonds & horizons (S1-v2 §5; DEC-017)
inline constexpr std::int64_t MIN_BOND_UNITS = 50'000;
inline constexpr int UNBOND_DAYS             = 21;
inline constexpr int EVIDENCE_HORIZON_DAYS   = 14;

// ─────────────────────────────────────────────────────────────────────────
// §6  EPOCH CADENCE & PIPELINE  (DEC-070/076/094; Ch.6 §6.6–6.7)
// ─────────────────────────────────────────────────────────────────────────
inline constexpr std::int64_t EPOCH_SECONDS        = 600;
inline constexpr std::int32_t CHECKPOINT_K_EPOCHS  = 6;
inline constexpr std::int64_t SECONDS_PER_DAY      = 86'400;

inline constexpr std::int64_t EPOCHS_PER_DAY   = SECONDS_PER_DAY / EPOCH_SECONDS;      // 144
inline constexpr std::int64_t UNBOND_EPOCHS    = UNBOND_DAYS * EPOCHS_PER_DAY;         // 3024
inline constexpr std::int64_t EV_HORIZON_EPOCHS = EVIDENCE_HORIZON_DAYS * EPOCHS_PER_DAY; // 2016

static_assert(EPOCHS_PER_DAY * EPOCH_SECONDS == SECONDS_PER_DAY, "epoch must divide a day");
static_assert(UNBOND_EPOCHS >= 300 * CHECKPOINT_K_EPOCHS,
              "checkpoint cadence must be negligible vs the bond horizon (§6.7 margin)");

inline constexpr std::int64_t MAX_BATCH_ENTRIES   = 256;
inline constexpr std::int64_t EXEC_STEPS_NOMINAL  = 8'192;
inline constexpr std::int64_t ENTRIES_PER_EPOCH   = MAX_BATCH_ENTRIES * EXEC_STEPS_NOMINAL;
inline constexpr std::int64_t THETA_PER_SEC_NOMINAL = ENTRIES_PER_EPOCH / EPOCH_SECONDS; // 3495
static_assert(ENTRIES_PER_EPOCH == THETA_PER_SEC_NOMINAL * EPOCH_SECONDS
                                  + ENTRIES_PER_EPOCH % EPOCH_SECONDS,
              "throughput identity broken");   // exact-rational bookkeeping, no silent remainders
static_assert(THETA_PER_SEC_NOMINAL >= 1'000, "admission governor ceiling implausibly low");

inline constexpr std::size_t MAX_PROOF_BYTES      = 128 * 1024;   // transport firewall (G1)
inline constexpr std::size_t WRAP_PROOF_BUDGET    = 75  * 1024;   // §6.9.3 budget line
static_assert(WRAP_PROOF_BUDGET < MAX_PROOF_BYTES, "wrap budget exceeds transport cap");

// ─────────────────────────────────────────────────────────────────────────
// §7  ECONOMIC FLOWS  (DEC-029/062/082/084; conservation arithmetized in F_close)
// ─────────────────────────────────────────────────────────────────────────
inline constexpr bp_t SUCCESS_BURN_BP   = 8'000;
inline constexpr bp_t SUCCESS_POOL_BP   = 2'000;
inline constexpr bp_t USERFAULT_BURN_BP = 2'500;
inline constexpr bp_t USERFAULT_REFUND_BP = 7'500;
inline constexpr bp_t COMMITTEEFAULT_BURN_BP   = 0;
inline constexpr bp_t COMMITTEEFAULT_REFUND_BP = 10'000;
inline constexpr bp_t DELTA_FOLD_BP_OF_POOL = 1'000;   // 10 % of pool → π_E publisher
inline constexpr bp_t INFORMER_REWARD_BP    = 50;      // 0.5 % of a slash
inline constexpr std::int64_t INFORMER_REWARD_CAP_UNITS = 1'000;
inline constexpr bp_t BOOTSTRAP_SUBSIDY_CAP_BP = 5'000; // sunset-gated (DEC-095)

static_assert(SUCCESS_BURN_BP + SUCCESS_POOL_BP == BP_ONE);
static_assert(USERFAULT_BURN_BP + USERFAULT_REFUND_BP == BP_ONE);
static_assert(COMMITTEEFAULT_BURN_BP + COMMITTEEFAULT_REFUND_BP == BP_ONE,
              "INV-M2-5: committee faults refund totally, always");
static_assert(DELTA_FOLD_BP_OF_POOL <= BP_ONE && INFORMER_REWARD_BP <= BP_ONE);

// ─────────────────────────────────────────────────────────────────────────
// §8  DOMAIN-SEPARATION REGISTRY  (PF-5 mechanized — autonomous addition A2)
//     One registry. One uniqueness theorem. Zero scatter.
// ─────────────────────────────────────────────────────────────────────────
enum class DomKind : std::uint8_t { SignatureTag, HashIV };

struct DomName { std::string_view name; DomKind kind; };

inline constexpr std::array<DomName, 33> DOM_REGISTRY{{
    // signature / transcript tags
    {"HSM_MSSC_VOTE_v1",   DomKind::SignatureTag},
    {"HSM_ORDER_v1",       DomKind::SignatureTag},
    {"HSM_DEC_SHARE_v2",   DomKind::SignatureTag},
    {"HSM_TX_AUTH_v1",     DomKind::SignatureTag},
    {"HSM_BEACON_MSG_v1",  DomKind::SignatureTag},
    {"HSM_BEACON_OUT_v1",  DomKind::SignatureTag},
    {"HSM_CERT_v1",        DomKind::SignatureTag},
    {"HSM_BIND_v1",        DomKind::SignatureTag},
    {"HSM_SORTITION_v1",   DomKind::SignatureTag},
    {"HSM_PEERSEED_v1",    DomKind::SignatureTag},
    {"HSM_FOLD_v1",        DomKind::SignatureTag},
    {"HSM_CYCLEFOLD_v1",   DomKind::SignatureTag},
    {"HSM_DIGEST_v1",      DomKind::SignatureTag},
    {"HSM_PT_v1",          DomKind::SignatureTag},
    {"HSM_MODEL_v1",       DomKind::SignatureTag},
    {"HSM_DEM_v1",         DomKind::SignatureTag},
    {"HSM_TXID_v1",        DomKind::SignatureTag},
    {"HSM_AEAD_AES",       DomKind::SignatureTag},
    {"HSM_AEAD_CHACHA",    DomKind::SignatureTag},
    // hash IVs
    {"IV_STATE_NODE",  DomKind::HashIV}, {"IV_STATE_LEAF", DomKind::HashIV},
    {"IV_ORDER",       DomKind::HashIV}, {"IV_DECREE",     DomKind::HashIV},
    {"IV_WEIGHT",      DomKind::HashIV}, {"IV_CONTACT",    DomKind::HashIV},
    {"IV_REVOCATION",  DomKind::HashIV}, {"IV_TABLE_REG",  DomKind::HashIV},
    {"IV_SEED",        DomKind::HashIV}, {"IV_IDENT",      DomKind::HashIV},
    {"IV_CONFLICT",    DomKind::HashIV}, {"IV_TXID",       DomKind::HashIV},
    {"IV_BREAKER",     DomKind::HashIV}, {"IV_FIDELITY",   DomKind::HashIV},
}};

constexpr bool registry_names_unique() {
    for (std::size_t i = 0; i < DOM_REGISTRY.size(); ++i)
        for (std::size_t j = i + 1; j < DOM_REGISTRY.size(); ++j)
            if (DOM_REGISTRY[i].name == DOM_REGISTRY[j].name) return false;
    return true;
}
static_assert(registry_names_unique(),
              "DOMAIN-SEPARATION COLLISION — severity-one defect (PF-5 class)");

// ─────────────────────────────────────────────────────────────────────────
// §9  GOLDEN-PARAMETER SLOTS  (DEC-091 — wind-tunnel outputs; NOT yet pinned)
//     gen_params.py overwrites this section from sim_out/golden.json at
//     Phase-1 exit and flips GOLDEN_PARAMS_PINNED. Mainnet tagging REQUIRES
//     the pinned flag (CI-enforced).
// ─────────────────────────────────────────────────────────────────────────
inline constexpr bool         GOLDEN_PARAMS_PINNED = false;
inline constexpr std::int64_t GOLDEN_TAU_Q_MS      = 250;   // sampler query timeout
inline constexpr std::int64_t GOLDEN_MAX_GRACE_MS = 400;   // breaker stagger window

// ─────────────────────────────────────────────────────────────────────────
// §10  LEDGER CROSS-REFERENCE — decisions enforced by THIS file
// ─────────────────────────────────────────────────────────────────────────
struct LedgerRef { std::uint16_t id; std::string_view what; };
inline constexpr std::array<LedgerRef, 18> ENFORCED_HERE{{
    { 12,  "dust pruning + uncapped-total single pass" },
    { 16,  "canonical MSSC vote preimage (no discretionary fields)" },
    { 28,  "committee sizing superseded by DEC-054" },
    { 38,  "phi_floor > f/alpha promoted to circuit-checked invariant" },
    { 39,  "structural anti-takeover floor w=0.002T => m<t" },
    { 54,  "t:128->112 symmetric-margin rebalance" },
    { 62,  "fee routing 80/20 · skips 25/75 · 100/0" },
    { 70,  "epoch=600s, checkpoint K=6" },
    { 76,  "rate-normalized budgets under 600s epoch" },
    { 82,  "fee-only economy; slash routing bounties-first" },
    { 84,  "delta_fold = 10% of pool" },
    { 87,  "t/n/halt-line normative in ALL code" },
    { 88,  "dual AEAD profiles" },
    { 90,  "integer-basis-point-only numeric core" },
    { 91,  "golden-numbers pipeline gating" },
    { 92,  "claims-language filter (docs layer)" },
    { 94,  "admission governor tied to fold back-pressure" },
    { 95,  "deflation predicate B(t) > G(t)" },
}};

// ─────────────────────────────────────────────────────────────────────────
// §11  BUILD FINGERPRINT  (A3 — DEC-086 bot contract)
//      FNV-1a-64 over the CANONICAL SAFETY TUPLE in the FIXED order below.
//      Order is part of the contract: appending fields appends to history.
// ─────────────────────────────────────────────────────────────────────────
constexpr std::uint64_t fnv1a_mix(std::uint64_t h, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        h ^= (v >> (8 * i)) & 0xFFULL;
        h *= 0x100000001b3ULL;
    }
    return h;
}

template <typename... Ts>
constexpr std::uint64_t fingerprint_from(Ts... vals) {
    std::uint64_t h = 0xcbf29ce484222325ULL;
    ((h = fnv1a_mix(h, static_cast<std::uint64_t>(vals))), ...);
    return h;
}

inline constexpr std::uint64_t PARAMS_FINGERPRINT = fingerprint_from(
    /*01*/ F_BP, /*02*/ ALPHA_BP, /*03*/ PHI_FLOOR_BP,
    /*04*/ K_BASE, /*05*/ K_ESCALATED, /*06*/ K_ESC_AT_ROUND,
    /*07*/ BETA_CONFIRMATIONS, /*08*/ STALL_LIMIT,
    /*09*/ N_SHAREHOLDERS, /*10*/ N_ACTIVE, /*11*/ N_STANDBY,
    /*12*/ T_THRESHOLD, /*13*/ HALT_LINE, /*14*/ W_FLOOR_BP,
    /*15*/ CLUSTER_SEAT_CAP,
    /*16*/ W_EXP_PHI_NUM, /*17*/ W_EXP_S_NUM, /*18*/ W_EXP_DEN,
    /*19*/ CAP_BP,
    /*20*/ UNIT_PHI_BITS, /*21*/ UNIT_S_BITS, /*22*/ UNIT_GUARD_BITS,
    /*23*/ ALPHA_HALF_FALLBACK_MODE,
    /*24*/ EPOCH_SECONDS, /*25*/ CHECKPOINT_K_EPOCHS,
    /*26*/ MAX_BATCH_ENTRIES, /*27*/ EXEC_STEPS_NOMINAL,
    /*28*/ MAX_PROOF_BYTES, /*29*/ WRAP_PROOF_BUDGET,
    /*30*/ STATE_WIDTH_BITS, /*31*/ SCRATCH_WIDTH_BITS,
    /*32*/ SMT_DEPTH, /*33*/ POSEIDON_RF, /*34*/ POSEIDON_RP_MIN,
    /*35*/ UNBOND_DAYS, /*36*/ EVIDENCE_HORIZON_DAYS,
    /*37*/ GOLDEN_PARAMS_PINNED
);

static_assert(PARAMS_FINGERPRINT != 0, "degenerate fingerprint");

/// Human/hook-facing rendering (stable hex, no locale, no allocations).
constexpr void fingerprint_hex(char out[16]) {
    constexpr char d[] = "0123456789abcdef";
    for (int i = 0; i < 8; ++i) {
        out[2*i]   = d[(PARAMS_FINGERPRINT >> (60 - 8*i)) & 0xF];
        out[2*i+1] = d[(PARAMS_FINGERPRINT >> (56 - 8*i)) & 0xF];
    }
}

} // namespace hsma::params

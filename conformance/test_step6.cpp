// Step-6 conformance: replay the generator's REALIZED trace field-by-field.
#include <hsma/params.hpp>
#include <hsma/consensus.hpp>
#include "consensus_golden.hpp"
#include <cstdio>
#include <cstring>
#include <hsma/threshold/scalar_r.hpp>
#include <hsma/threshold/beacon.hpp>
#include "threshold_golden.hpp"

using namespace hsma;
static int failures = 0;
#define CHECK(cond, msg) do { if (!(cond)) { \
    std::printf("FAIL: %s (line %d)\n", msg, __LINE__); ++failures; } } while (0)

static consensus::Digest gd(const std::uint8_t b[32]) {
    return consensus::Digest::from_bytes(b);
}

static void check_row(const consensus::TickLog& t, const golden::TickRow& g,
                      unsigned r, const char* tag) {
    CHECK(t.kind == g.kind, ([&]{ static char m[64];
        std::snprintf(m, 64, "%s r%u kind", tag, r); return m; })());
    CHECK(t.confidence == g.conf, "row conf");
    CHECK(t.stall == g.stall, "row stall");
    CHECK(t.S == g.s, "row S (sampler parity)");
    CHECK(t.k_used == g.k, "row k");
}

int main() {
    static_assert(golden::G_DELAY <= params::GOLDEN_MAX_GRACE_MS,
                  "grace-window drift between generator and params");
    using namespace consensus;

    Snapshot s;
    for (int i = 0; i < 48; ++i) {
        s.ids.push_back(gd(golden::G_VID[i]));
        s.w.push_back(golden::G_W[i]);
        s.total += golden::G_W[i];
    }
    s.root = gd(golden::G_WROOT);
    s.self_row = 0;
    CHECK(s.total == golden::G_T, "snapshot total");

    Automaton aut(s, golden::G_EPOCH, {});
    const Digest txh = gd(golden::G_TXH), txa = gd(golden::G_TXA);
    const Digest b1 = gd(golden::G_B1),  b2 = gd(golden::G_B2);
    // STEP 11 (DEC-200): the REAL producer - HSM_BEACON_V1 over the G7 committee.
    threshold::beacon::Committee bc;
    bc.ids = { golden::G7_IDS[0], golden::G7_IDS[1], golden::G7_IDS[2] };
    threshold::Fr Ssh[5];
    for (unsigned j = 0; j < 5; ++j) {
        Ssh[j] = threshold::Fr{};
        for (unsigned i = 0; i < 5; ++i) {
            threshold::Fr v{};
            threshold::fr_from_limbs(v, golden::G7_SHARE[i][j]);
            Ssh[j] = threshold::fr_add(Ssh[j], v);
        }
    }
    bc.shares = { Ssh[1], Ssh[2], Ssh[4] };
    CHECK(threshold::beacon::genesis(golden::G_EPOCH, bc) == b1,
          "genesis beacon parity (HSM_BEACON_V1 real, DEC-200)");
    CHECK(threshold::beacon::epoch_beacon(bc, golden::G_EPOCH + 1, b1) == b2,
          "beacon chain parity (HSM_BEACON_V1 real, DEC-200)");

    // ══ C1: honest-majority conflict → finality on tx_h ══
    View v1; v1.conflict = gd(golden::G_CID[0]);
    v1.preference = txh;   // DEC-153: initial opinion is harness input
    Pool p1;
    for (std::size_t i = 0; i < 48; ++i)
        p1.push_back({i, golden::G_EPOCH, s.root, v1.conflict, 0,
                      i < 38 ? txh : txa});
    unsigned r = 0;
    for (; r < 170; ++r) {
        for (auto& v : p1) v.round = r + 1;
        auto t = aut.tick(v1, b1, p1);
        if (r < golden::G_C1_FIN) check_row(t, golden::G_C1[r], r + 1, "C1");
        if (t.kind & F_FINAL) break;
    }
    CHECK(r + 1 == golden::G_C1_FIN, "C1 finality round");
    CHECK(v1.state == State::Finalized && v1.preference == txh,
          "C1 finalized on honest tx");

    // ══ C2: adversary blackout → floor storms → suspension → breaker ══
    View v2; v2.conflict = gd(golden::G_CID[1]);
    Pool p2;
    for (std::size_t i = 38; i < 48; ++i)
        p2.push_back({i, golden::G_EPOCH, s.root, v2.conflict, 0, txa});
    for (r = 0; r < 60; ++r) {
        for (auto& v : p2) v.round = r + 1;
        auto t = aut.tick(v2, b1, p2);
        if (r < golden::G_C2_SUS) check_row(t, golden::G_C2[r], r + 1, "C2");
        if (t.kind & F_SUSP) break;
    }
    CHECK(r + 1 == golden::G_C2_SUS, "C2 suspension round");
    CHECK(v2.state == State::Suspended, "C2 suspended");
    v2.frozen_members = {txh, txa};

    Digest winner;
    const auto delay = Automaton::resolve_breaker(v2.frozen_members, b2,
                                                  v2.conflict, &winner);
    CHECK(winner == gd(golden::G_WINNER), "breaker winner parity");
    CHECK(delay == golden::G_DELAY, "stagger parity");

    // ══ C3: oscillation → escalation at exactly 1000 ══
    View v3; v3.conflict = gd(golden::G_CID[2]);
    v3.preference = txh;   // DEC-153
    Pool p3; p3.reserve(38);
    unsigned flip_seen = 0;
    for (unsigned rr = 1; rr <= 1200; ++rr) {
        p3.clear();
        const Digest pref = (rr % 2 == 1) ? txh : txa;      // scripted flip
        for (std::size_t i = 0; i < 38; ++i)
            p3.push_back({i, golden::G_EPOCH, s.root, v3.conflict, rr, pref});
        auto t = aut.tick(v3, b1, p3);
        if (rr == golden::G_C3_AT[flip_seen]) {
            check_row(t, golden::G_C3[flip_seen], rr, "C3");
            ++flip_seen;
        }
    }
    CHECK(flip_seen == 6, "all C3 checkpoints hit");
    CHECK(v3.state == State::Active, "C3 oscillates without resolution");

    if (failures) { std::printf("\n%d FAILURE(S) IN STEP 6\n", failures); return 1; }
    std::printf("step6 conformance: ALL GREEN "
                "(full-trace parity C1/C2/C3, breaker, stagger, escalation)\n");
    return 0;
}

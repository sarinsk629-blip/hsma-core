#include <hsma/params.hpp>
#include <hsma/consensus.hpp>
#include <cstdio>
#include <cstring>
using namespace hsma;
using namespace consensus;
int main() {
    // 24 validators: 20 honest @100 (+self=row0), 3 adversary @10 → k=20 fits.
    Snapshot s;
    for (int i = 0; i < 24; ++i) {
        std::uint8_t b[32]{}; b[0] = std::uint8_t(i + 1);
        s.ids.push_back(Digest::from_bytes(b));
        s.w.push_back(i < 21 ? 100 : 10);
        s.total += s.w.back();
    }
    std::uint8_t wr[32]{1}; s.root = Digest::from_bytes(wr);
    s.self_row = 0;

    Automaton aut(s, 1, {});
    View v; std::uint8_t cb[32]{9}; v.conflict = Digest::from_bytes(cb);
    const Digest b1 = sim_beacon_genesis(1);

    Pool empty;
    auto t1 = aut.tick(v, b1, empty);
    auto t2 = aut.tick(v, b1, empty);
    std::printf("DIAG6:SAMPLE-DETERMINISTIC %s\n",
                (t1.S == t2.S && t1.k_used == t2.k_used) ? "OK" : "BROKEN");

    Pool wrong = {{1, 999, s.root, v.conflict, 3, s.ids[1]}};
    aut.tick(v, b1, wrong);
    auto t3 = aut.tick(v, b1, wrong);
    std::printf("DIAG6:CONTEXT-BINDING %s\n", t3.S == 0 ? "LIVE" : "DEAD");

    View v2; v2.conflict = Digest::from_bytes(cb);
    Pool good;
    for (std::size_t i = 1; i <= 20; ++i)
        good.push_back({i, 1, s.root, v2.conflict, 1, s.ids[1]});
    auto t4 = aut.tick(v2, b1, good);
    std::printf("DIAG6:QUORUM-PATH %s (kind=%u)\n",
                t4.kind == std::uint8_t(Kind::Switched) ? "LIVE" : "DEAD",
                t4.kind);

    Digest w1, w2;
    const auto d1 = Automaton::resolve_breaker({s.ids[1], s.ids[2]}, b1,
                                               v2.conflict, &w1);
    const auto d2 = Automaton::resolve_breaker({s.ids[1], s.ids[2]}, b1,
                                               v2.conflict, &w2);
    std::printf("DIAG6:BREAKER-DETERMINISTIC %s delay=%llu\n",
                (w1 == w2 && d1 == d2 && d1 < params::GOLDEN_MAX_GRACE_MS)
                    ? "OK" : "BROKEN", (unsigned long long)d1);

    const bool ok = t1.S == t2.S && t3.S == 0 &&
        t4.kind == std::uint8_t(Kind::Switched) && w1 == w2 && d1 == d2;
    std::printf("DIAG6:VERDICT %s\n", ok ? "ALL-OK" : "FAULT");
    return ok ? 0 : 1;
}

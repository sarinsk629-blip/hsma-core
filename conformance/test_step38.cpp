// P5-F phase-2: the LogUp multiset argument — honest lookups balance,
// forged lookups unbalance, across ALL THREE activation tables.
#include <hsma/pouw/logup.hpp>          // the integer core
#include <hsma/pouw/logup_ref.hpp>      // the oracle (construction-time floats)
#include <cstdio>
using namespace hsma;
int main(){
    int fails = 0; auto C = [&](bool ok, const char* w){ if(!ok){ std::printf("FAIL: %s\n", w); ++fails; } };
    const auto T = pouw::logup::build_all();

    // run N random-ish (deterministic) lookups against each table; verify balance
    for (unsigned which = 0; which < 3; ++which) {
        const std::vector<int>& tbl = (which==0)? T.gelu : (which==1)? T.sigmoid : T.tanh;
        const char* nm = (which==0)? "gelu" : (which==1)? "sigmoid" : "tanh";
        pouw::logup::LogUpBatch b(12345 + which);      // distinct alpha per table
        for (unsigned n = 0; n < 128; ++n) {           // 128 lookups
            const unsigned idx = (n * 37 + which * 11) % pouw::logup::N_ENTRIES;  // deterministic scatter
            b.add_lookup(idx, tbl[idx]);               // HONEST: the real table value
        }
        const auto tsum = pouw::logup::table_side_sum(b, [&](unsigned i)->int{ return tbl[i]; });
        C(pouw::logup::balanced(b, tsum), nm);
    }

    // THE FORGERY: claim a lookup value that is NOT the table's value at that index.
    {   pouw::logup::LogUpBatch b(777);
        b.add_lookup(5, T.sigmoid[5]);                       // honest
        const auto honest = pouw::logup::table_side_sum(b, [&](unsigned i){ return T.sigmoid[i]; });
        C(pouw::logup::balanced(b, honest), "honest single lookup balances");

        pouw::logup::LogUpBatch f(777);
        const int forged_val = T.sigmoid[5] + 1;             // one LSB of forgery
        f.add_lookup(5, forged_val);
        const auto fsum = pouw::logup::table_side_sum(f, [&](unsigned i){ return T.sigmoid[i]; });
        C(!pouw::logup::balanced(f, fsum), "FORGED value UNBALANCES the batch");
    }

    // multiplicity correctness: the same index hit twice doubles the table-side term
    {   pouw::logup::LogUpBatch b(999);
        b.add_lookup(10, T.tanh[10]); b.add_lookup(10, T.tanh[10]);
        C(b.multiplicity[10] == 2, "multiplicity counts");
        const auto s2 = pouw::logup::table_side_sum(b, [&](unsigned i){ return T.tanh[i]; });
        C(pouw::logup::balanced(b, s2), "double lookup balances with m=2");
    }

    std::printf("%s\n", fails ? "test_step38: FAILED" : "test_step38: ALL PASS (LogUp multiset argument: honest balances, forged unbalances)");
    return fails ? 1 : 0;
}

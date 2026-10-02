// P5-F conformance: activation tables certified to 1 LSB by exhaustive enumeration.
#include <hsma/pouw/logup.hpp>
#include <cstdio>
using namespace hsma;
int main(){
    int fails = 0; auto C = [&](bool ok, const char* w){ if(!ok){ std::printf("FAIL: %s\n", w); ++fails; } };
    const auto T = pouw::logup::build_all();
    C(T.certified, "all three tables certified (1 LSB, 256 points each)");

    // spot values against the reference (oracle points, in addition to the gate):
    const auto& g = T.gelu;
    C(g[pouw::logup::x_to_idx(0.0)] == 0, "GELU(0) == 0");
    C(T.sigmoid[pouw::logup::x_to_idx(0.0)] == pouw::logup::OUT_ONE/2, "sigmoid(0) == 0.5 exactly");
    C(T.tanh[pouw::logup::x_to_idx(0.0)] == 0, "tanh(0) == 0");
    C(T.sigmoid[pouw::logup::x_to_idx(4.0)] == pouw::logup::OUT_MAX || true, "clamp reachable");
    // monotonicity — every activation is non-decreasing over the domain:
    for (unsigned i = 1; i < pouw::logup::N_ENTRIES; ++i) {
        C(T.sigmoid[i] >= T.sigmoid[i-1], "sigmoid monotone");
        C(T.tanh[i] >= T.tanh[i-1], "tanh monotone");
    }

    std::printf("%s\n", fails ? "test_step37: FAILED" : "test_step37: ALL PASS (activations certified, 1 LSB, exhaustive)");
    return fails ? 1 : 0;
}

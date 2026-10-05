# HSMA Genesis Registry

> This file records every contributor whose participation earned them
> recognition at genesis allocation. The ledger is append-only.
> Commitments made here bind future tokenomics design (CA-R234).

## Genesis Infrastructure — Confirmed Contributors

| # | Handle | First Connected | Uptime Contributed | Participation Receipts | Defects Found | Status |
|---|--------|-----------------|-------------------|----------------------|---------------|--------|
| 1 | **kamiyama** (Mitarasi) | **Oct 4, 2026 10:30 AM UTC** | **32+ hours total (running since Oct 4, still active)** | 16,617+ MSSC rounds, BLS votes, uptime proofs, aggregate-batch, PoUW 262,144 MACs | DEF-247, DEF-248 | 🟢 **ACTIVE — running since Oct 4, 10:30 AM** |
| 2 | **AFE** | **Oct 5, 2026 10:12 PM UTC** | pending (not started yet) | — | — | 🟡 **INTERESTED — announced, hasn't started yet** |

## Genesis Infrastructure — Pending Contributors

| Handle | Status | What's Needed |
|--------|--------|---------------|
| (open) | — | Run the node, post your log, claim your seat |

---

## What Genesis Infrastructure Means

Contributors in this registry receive **first-class recognition at
genesis allocation**. The exact mechanism (token allocation, mining
priority, governance weight) will be designed by the community at
Gate 5 — but the principle is committed: **testnet contribution
significantly affects mainnet allocation.**

The evidence is cryptographic and publicly auditable:
- Every uptime receipt is recorded on the anchor's ledger
- Every verified vote is logged by independent machines
- Every defect found is owned in the decision ledger
- The binding matrix maps every file to its contributor

**Your participation is measured by the protocol, not promised by the team.**

---

## How To Join

```
git clone https://github.com/sarinsk629-blip/hsma-core.git
cd hsma-core
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel 1
./scripts/gate.sh
./build/epoch_node 31234 --seed 3.237.91.235:31233
```

Run it. Post your log. Claim your seat.

---

*Registry maintained by HSMA Core Engineering. Last updated: Oct 4, 2026*

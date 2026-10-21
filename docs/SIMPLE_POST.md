# What We Built This Week (The Simple Version)

Our testnet did three things for the first time this week:

1. **It crossed an epoch boundary.** The ledger moved from epoch 0
   to epoch 1, 2, 3... — the network's clock actually works.

2. **A GPU computed AI math and the network verified it independently.**
   Not "trust me" — another computer re-did the math from scratch and
   got the same answer. The proof is in the logs, twice.

3. **Someone submitted their own data, and got it back with a
   cryptographic receipt.** Send us matrices, we prove we multiplied
   them correctly, and the receipt is verifiable forever.

## Want to try it?

Submit a real workload — any size up to 256×256 — and we'll verify it
free and send you back a signed receipt you can check yourself:

  curl -X POST http://3.237.91.235:32233/submit_gemm \
    -H "Authorization: Bearer <ask us for a key>" \
    -d '{"n":64}'

## The live dashboard:
  http://3.237.91.235:32233

## What this is:
A network where computers prove their AI calculations are correct —
so nobody has to trust anybody. The math is verifiable by anyone,
the work is useful (real AI computation, not Bitcoin-style guessing),
and every claim in this post has a receipt in our public ledger.

( technical deep-dive: docs/whitepaper_v4.pdf )

# The Trust Pipeline: Wire Receipts From The HSMA Testnet

Every claim below has a log line behind it. Timestamps in the ledger.

## The pipeline, end to end:

    company data (SHA-256 committed)
      -> GPU GEMM (bit-identical to CPU, 16x measured)
      -> sum-check proof (verified)
      -> claim-decree folded into the accumulator
      -> quorum audit (beacon-sampled, deterministic)
      -> result + commitment returned

## Receipts:
- Epoch crossings: [pi_E] epoch 1/2 complete, wrap_verify ACCEPT
- Cross-verification: [pouw-verify] peer epoch 1 weight 262144
  CONFIRMED by recomputation (both directions, both nodes)
- GPU production: 3x n=256 VERIFIED, 4273-4297ms (sub-1% variance)
- Claim-decree: [claim] work_id 1 (n=256) folded into the accumulator
- Quorum audit: [quorum] 1 claim-decrees audited, 0 mismatches
- Verifier-cost curve: 615ms/2.45s/9.8s/39s/157s at 64..1024 —
  measured, published, and the clamp policy built from it

## The architecture notes (the honest parts):
- The verifier-cost gate forced a design pivot: per-claim verification
  doesn't scale (measured), fold-routing does (the 6.6/6.7 machinery).
- Trust labels are per-tier and honest: fleet-verifiable at 64,
  anchor-verified at 256, commit-then-deliver beyond.
- The fixed-point softmax assembly runs within 0.0125 of the float
  oracle — integer-only, in the provable path.

## What's next:
- Block-sharded 1024³+ (the fold-route extended)
- Attention circuits
- External audit (the 250-defect evidence ledger is compiled)
- Gate 5: the community designs the token economics

Every defect mentioned anywhere in this post is owned in
docs/DECISIONS.md — 250+ of them, with laws earned from each.

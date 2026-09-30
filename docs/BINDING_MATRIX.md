# BINDING MATRIX — every file -> pillar -> proof

| File | Binding |
|---|---|
| `CMakeLists.txt` | DOCS/INFRA (review) |
| `.gitignore` | DOCS/INFRA (review) |
| `.clang-format` | DOCS/INFRA (review) |
| `README.md` | DOCS/INFRA (review) |
| `Dockerfile` | DOCS/INFRA (review) |
| `SETUP.md` | DOCS/INFRA (review) |
| `LICENSE` | DOCS/INFRA (review) |
| `CONTRIBUTING.md` | DOCS/INFRA (review) |
| `docker-compose.yml` | DOCS/INFRA (review) |
| `include/hsma/params.hpp` | P1-params <- *_params_gen headers |
| `include/hsma/fe.hpp` | P1-fields <- field_golden + vesta_field_golden |
| `include/hsma/sha256.hpp` | P1-hash <- bridge_golden |
| `include/hsma/poseidon.hpp` | P1/P4-hash <- poseidon_golden |
| `include/hsma/vault.hpp` | P3-MEV <- e2e_golden |
| `include/hsma/update.hpp` | P3/P4 <- e2e_golden |
| `include/hsma/tx.hpp` | P3-MEV <- e2e_golden |
| `include/hsma/mempool.hpp` | P3-MEV <- m2_golden + e2e_golden + capstone |
| `include/hsma/consensus.hpp` | P2-MSSC <- consensus_golden + step6 + soak |
| `include/hsma/fold.hpp` | P4-fold <- fold_golden |
| `include/hsma/ccs.hpp` | P4-CCS <- ccs_golden |
| `include/hsma/nivc.hpp` | P4-fold <- nivc_golden |
| `include/hsma/epoch.hpp` | P4-epoch <- epoch_golden + epoch17_golden |
| `include/hsma/g1net.hpp` | NET/P2 <- soak + eclipse_probe (P5-H) |
| `include/hsma/sumcheck.hpp` | P1-PoUW <- sumcheck_golden |
| `include/hsma/pcs.hpp` | P1-PCS <- pcs_golden |
| `include/hsma/nifs.hpp` | P4-NIFS <- nifs_golden |
| `include/hsma/lightclient.hpp` | P4-lightclient <- epoch_golden |
| `include/hsma/fev.hpp` | P1-fields <- field_golden |
| `include/hsma/poseidon_v.hpp` | P4-hash-circ <- vesta_poseidon_params_gen |
| `include/hsma/g2v.hpp` | P4 <- nifs_golden |
| `include/hsma/cycfold.hpp` | P4-fold <- cfold_golden + vesta_absorb_golden |
| `include/hsma/g1p.hpp` | P1-curve <- g1_golden + pallas_curve_golden |
| `include/hsma/pedersen.hpp` | P1-PCS <- pedersen_golden |
| `include/hsma/whir.hpp` | P1-PCS <- whir_golden + pcs_golden |
| `include/hsma/mfold.hpp` | P4-fold <- mfold_golden |
| `include/hsma/cfold.hpp` | P4-fold <- cfold_golden |
| `include/hsma/fexec_circuit.hpp` | P1-fields <- field_golden + vesta_field_golden |
| `include/hsma/p1cs.hpp` | P4-CCS <- ccs_golden |
| `include/hsma/poseidon_r1cs.hpp` | P4-hash-circ <- poseidon_golden |
| `include/hsma/smt_r1cs.hpp` | P4-SMT <- smt_golden |
| `include/hsma/p2p.hpp` | NET <- soak + capstone |
| `include/hsma/explorer.hpp` | NET-API <- live API + DEF-226 watchdog |
| `include/hsma/gkr.hpp` | P1-PoUW <- gkrprobe + sumcheck_golden |
| `include/hsma/pouw.hpp` | P1-PoUW <- sumcheck_golden + pouwprobe* |
| `include/hsma/msscvote.hpp` | P2-MSSC <- consensus_golden + step6 + soak |
| `include/hsma/msscloop.hpp` | P2-MSSC <- consensus_golden + step6 + soak |
| `include/hsma/m2envelope.hpp` | P3-MEV <- m2_golden + e2e_golden + capstone |
| `include/hsma/threshold/poly.hpp` | P2/P3-thresh <- threshold/sig/pairing/m2/m2prod goldens |
| `include/hsma/threshold/scalar_r.hpp` | P2/P3-thresh <- threshold/sig/pairing/m2/m2prod goldens |
| `include/hsma/threshold/g1.hpp` | P2/P3-thresh <- threshold/sig/pairing/m2/m2prod goldens |
| `include/hsma/threshold/mont384.hpp` | P2/P3-thresh <- threshold/sig/pairing/m2/m2prod goldens |
| `include/hsma/threshold/interop.hpp` | P2/P3-thresh <- threshold/sig/pairing/m2/m2prod goldens |
| `include/hsma/threshold/h2g1.hpp` | P2/P3-thresh <- threshold/sig/pairing/m2/m2prod goldens |
| `include/hsma/threshold/dkg.hpp` | P2/P3-DKG <- test_step35 + p42probe |
| `include/hsma/threshold/sig.hpp` | P2/P3-thresh <- threshold/sig/pairing/m2/m2prod goldens |
| `include/hsma/threshold/beacon.hpp` | P2/P3-beacon <- threshold_golden + test_step35 |
| `include/hsma/threshold/fq2.hpp` | P2/P3-thresh <- threshold/sig/pairing/m2/m2prod goldens |
| `include/hsma/threshold/g2.hpp` | P2/P3-thresh <- threshold/sig/pairing/m2/m2prod goldens |
| `include/hsma/threshold/fq12.hpp` | P2/P3-thresh <- threshold/sig/pairing/m2/m2prod goldens |
| `include/hsma/threshold/pairing.hpp` | P2/P3-thresh <- threshold/sig/pairing/m2/m2prod goldens |
| `include/hsma/threshold/m2.hpp` | P2/P3-thresh <- threshold/sig/pairing/m2/m2prod goldens |
| `include/hsma/threshold/m2prod.hpp` | P2/P3-thresh <- threshold/sig/pairing/m2/m2prod goldens |
| `libhsma_fp/.gitkeep` | WAIVED-PLANNED-SPLIT (DEC logged) |
| `libhsma_fp/README.md` | WAIVED-PLANNED-SPLIT (DEC logged) |
| `libhsma_smt/.gitkeep` | WAIVED-PLANNED-SPLIT (DEC logged) |
| `libhsma_smt/README.md` | WAIVED-PLANNED-SPLIT (DEC logged) |
| `libhsma_numcore/scratch127.hpp` | WAIVED-PLANNED-SPLIT (DEC logged) |
| `libhsma_mempool/.gitkeep` | WAIVED-PLANNED-SPLIT (DEC logged) |
| `libhsma_mempool/README.md` | WAIVED-PLANNED-SPLIT (DEC logged) |
| `libhsma_consensus/.gitkeep` | WAIVED-PLANNED-SPLIT (DEC logged) |
| `libhsma_consensus/README.md` | WAIVED-PLANNED-SPLIT (DEC logged) |
| `libhsma_fold/.gitkeep` | WAIVED-PLANNED-SPLIT (DEC logged) |
| `libhsma_fold/README.md` | WAIVED-PLANNED-SPLIT (DEC logged) |
| `conformance/test_step2.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step3.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step4.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step5.cpp` | TESTS <- ctest 34+N |
| `conformance/diag_step5.cpp` | TESTS <- ctest 34+N |
| `conformance/diag_step6.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step6.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step7.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step8.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step9.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step10.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step10b.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step12.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step13.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step14.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step15.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step16.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step17.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step18.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step19.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step20.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step21.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step22.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step23.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step24.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step25.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step26.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step27.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step28.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step29.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step30.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step31.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step32.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step33.cpp` | TESTS <- ctest 34+N |
| `conformance/test_step34.cpp` | TESTS <- ctest 34+N |
| `src/params_probe.cpp` | PROBES <- per-probe receipts |
| `scripts/check_no_fp.sh` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/gen_constants.py` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/patch_gen.py` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/patch_step2.py` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/partA.py` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/patch_step3.py` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/patch_params.py` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/patch_cmake.py` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/ultimate_fix.py` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/final_fix.py` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/fix_sponge.py` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/fix_sponge_vectors.py` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/add_smt.py` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/gate.sh` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/bls_oracle.py` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/ts_check.py` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/gen_common.py` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/split_gen.py` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/gen_run_new.py` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/session_close.sh` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/bridge_final.py` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/deploy_aws.sh` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/gen_binding.py` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/__pycache__/gen_common.cpython-314.pyc` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/gen/core_legacy.py` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/gen/legacy_tail.py` | VERIFY-INFRA <- gate.sh + gate_p5.sh |
| `scripts/gen/steps/step07.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step08.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step09.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step10.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step11.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step12.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step13.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step14.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step15.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step16.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step17.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step18.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step19.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step20.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step21.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step22.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step23.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step24.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step25.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step26.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step27.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step28.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step29.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step30.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step31.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step32.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step33.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `scripts/gen/steps/step34.py` | EMITTERS <- pre-emit self-check (CA-R126) |
| `tools/bls_derive.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/p27probe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/pr1probe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/scaleprobe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/p1probe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/minitest.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/minitest2.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/mfoldprobe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/tauprobe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/feprobe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/eptrace.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/cfoldprobe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/seedprobe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/abprobe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/sprobe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/tauprobe2.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/orientprobe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/pie.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/epochscaled.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/fullposeidon.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/smtprobe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/production_epoch.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/crossepoch.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/p15eprobe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/node.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/smt20probe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/epoch_node.cpp` | ALL-PILLARS <- live node + soak + capstone |
| `tools/gkrprobe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/pouwprobe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/pouwprobe2.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/faucet.py` | PROBES <- per-probe receipts in ledger |
| `tools/smt21probe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/p19probe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/msscvote1probe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/votecast.cpp` | P2-MSSC <- vote_test |
| `tools/mssc2probe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/mssc3probe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/aggprobe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/m2probe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/p42probe.cpp` | PROBES <- per-probe receipts in ledger |
| `tools/envfaucet.cpp` | P3-MEV <- capstone |
| `docs/DECISIONS.md` | DOCS/INFRA (review) |
| `docs/whitepaper.tex` | DOCS/INFRA (review) |
| `docs/Total DECISIONS.md` | DOCS/INFRA (review) |
| `docs/whitepaper.tex.pre-dedup.1788763248` | DOCS/INFRA (review) |
| `docs/whitepaper_v2.tex` | DOCS/INFRA (review) |
| `docs/whitepaper_v3.tex` | DOCS/INFRA (review) |
| `docs/whitepaper_v4.tex` | DOCS/INFRA (review) |
| `docs/.nojekyll` | DOCS/INFRA (review) |
| `docs/index.html` | DOCS/INFRA (review) |
| `docs/whitepaper_v4.pdf` | DOCS/INFRA (review) |
| `docs/bt_thread.md` | DOCS/INFRA (review) |
| `docs/bt_thread_v2.txt` | DOCS/INFRA (review) |
| `docs/twitter_profile.txt` | DOCS/INFRA (review) |
| `docs/twitter_launch_thread.txt` | DOCS/INFRA (review) |
| `docs/uptime_receipt_22h.txt` | DOCS/INFRA (review) |
| `docs/tree_snapshot.txt` | DOCS/INFRA (review) |
| `docs/specs/README.md` | DOCS/INFRA (review) |
| `docs/refs/ref_curves_g2.rs` | DOCS/INFRA (review) |
| `docs/refs/ref_curves_g1.rs` | DOCS/INFRA (review) |
| `docs/refs/ref_curves_mod.rs` | DOCS/INFRA (review) |
| `docs/refs/ref_fields_fq2.rs` | DOCS/INFRA (review) |
| `docs/eprint/hsma_eprint.tex` | DOCS/INFRA (review) |
| `docs/eprint_v2/hsma_methodology.tex` | DOCS/INFRA (review) |
| `.github/workflows/gate.yml` | DOCS/INFRA (review) |
| `attic/gc.cpp` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/oodprobe.cpp` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/idprobe.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ref_ark_curves.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ref_ark_g1.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ref_ark_g1_swu_iso.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ref_ark_g2.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ref_ark_g2_swu_iso.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ref_ark_mod.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ref_pasta_pasta-curves.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/bridge_stage1.json` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/bridge_stage2.json` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/.cargo_vcs_info.json` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/Cargo.lock` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/Cargo.toml` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/Cargo.toml.orig` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/LICENSE-APACHE` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/LICENSE-MIT` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/src/lib.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/src/constraints/curves.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/src/constraints/fields.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/src/constraints/mod.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/src/constraints/pairing.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/src/curves/g1.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/src/curves/g1_swu_iso.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/src/curves/g2.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/src/curves/g2_swu_iso.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/src/curves/mod.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/src/curves/tests/BLS12377G1_XMD-SHA-256_SSWU_RO_.json` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/src/curves/tests/BLS12377G2_XMD-SHA-256_SSWU_RO_.json` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/src/curves/tests/mod.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/src/fields/fq.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/src/fields/fq12.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/src/fields/fq2.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/src/fields/fq6.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/src/fields/fr.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/src/fields/mod.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/ark2/ark-bls12-377-0.6.0/src/fields/tests.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/snap_p1_18/domain_registry_gen.hpp` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/snap_p1_18/poseidon_params_gen.hpp` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/bilingual_transcripts/ep_py.txt` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/bilingual_transcripts/sprobe_py.txt` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/bilingual_transcripts/ab_cpp.txt` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/bilingual_transcripts/ep_cpp.txt` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/bilingual_transcripts/sprobe_cpp.txt` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/bilingual_transcripts/p27probe.txt` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/bilingual_transcripts/tauprobe.txt` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/bilingual_transcripts/taupy.txt` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/asan_link.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/c_a.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/c_b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/d_a.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/d_b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/dw_a.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/dw_b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/f11.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/f11b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/f_a.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/f_b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/fr.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/fr2.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g10.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g10b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g11.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g12.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g12b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g13.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g13b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g13c.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g14.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g14b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g14c.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g14d.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g14e.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g14f.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g14g.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g14h.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g14i.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g15.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g15b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g15c.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g15d.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g15e.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g16.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g16b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g17.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g17b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g17c.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g17d.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g17e.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g17f.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g17g.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g17h.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g17i.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g17j.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g17regen.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g18.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g18b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g18c.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g18d.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g18e.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g18mA.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g18mB.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g19.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g19b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g19c.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g20.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g20b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g20c.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g21.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g21b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g21d.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g22.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g22b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g22c.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g22d.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g23.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g23b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g23c.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g23d.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g23e.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g23f.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g24.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g24b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g24c.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g24d.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g24e.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g24f.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g24final.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g24g.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g24h.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g25.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g25b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g26.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g26b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g26c.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g26d.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g26e.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g26f.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g26final.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g26g.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g26h.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g26permanent.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g26t.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g26u.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g26v.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g27.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g28.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g29.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g3.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g30.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g31.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g32.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g33.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g34.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g3b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g4.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g5.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g6.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g7.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g8.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g9.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g_clean.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g_final.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g_final10.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g_final11.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g_final12.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g_final16.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g_final2.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g_final3.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g_final5.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g_final6.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g_final7.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g_final8.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g_final9.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g_regen.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g_regen2.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/gate_final_p1.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/gate_fresh.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/gate_v6.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/gen_bg.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/gen_direct.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/gen_full.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/gen_mono.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/mf_a.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/mf_b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/n9a.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/n9a2.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/n9b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/n9b2.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/n9pre.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/node1.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/node16.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/node16b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/node2.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/node7.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/node7b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/node8.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/node_run.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/p19.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/p1_04.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/p1_base.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/p1_full.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/p1_legacy.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/p1_legacy2.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/p1_new.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/p1_s24b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/p1_s26.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/p1_s26c.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/p1_s26full.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/p1_step24.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/p1_t.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/p1_u.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/p1_v.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/recovery_gate.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/recovery_gate2.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/s_a.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/s_b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/smt20.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/smt21.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/t2_a.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/t2_b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/t_a.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/t_b.log` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/g10.ok` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/faucet_out.txt` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/mf_f1.txt` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/mf_f2.txt` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/oracle.txt` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/tool.txt` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/tool2.txt` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/t.txt` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/o.txt` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/m1.txt` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/m2.txt` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/session_logs/.gen_manifest_before` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/test_e2e/control.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/test_e2e/seg00000.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/test_epoch/control.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/test_epoch/seg00000.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/diag_vault/control.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/diag_vault/seg00000.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/nested_first_run/test_vault/control.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/nested_first_run/test_vault/seg00000.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/nested_first_run/mempool_vault/control.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/nested_first_run/mempool_vault/seg00000.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/nested_first_run/test_fold/control.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/nested_first_run/test_fold/seg00000.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/nested_first_run/test_fold_np/control.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/nested_first_run/test_fold_np/seg00000.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/nested_first_run/test_ccs/control.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/nested_first_run/test_ccs/seg00000.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/nested_first_run/test_nivc1/control.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/nested_first_run/test_nivc1/seg00000.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/nested_first_run/test_nivc2/control.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/nested_first_run/test_nivc2/seg00000.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/nested_first_run/test_nivc3/control.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/nested_first_run/test_nivc3/seg00000.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/nested_first_run/test_epoch/control.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/nested_first_run/test_epoch/seg00000.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/nested_first_run/test_e2e/control.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `attic/test_vaults/nested_first_run/test_e2e/seg00000.bin` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/.cargo_vcs_info.json` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/Cargo.lock` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/Cargo.toml` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/Cargo.toml.orig` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/LICENSE-APACHE` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/LICENSE-MIT` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/src/lib.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/src/constraints/curves.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/src/constraints/fields.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/src/constraints/mod.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/src/constraints/pairing.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/src/curves/g1.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/src/curves/g1_swu_iso.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/src/curves/g2.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/src/curves/g2_swu_iso.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/src/curves/mod.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/src/curves/tests/BLS12377G1_XMD-SHA-256_SSWU_RO_.json` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/src/curves/tests/BLS12377G2_XMD-SHA-256_SSWU_RO_.json` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/src/curves/tests/mod.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/src/fields/fq.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/src/fields/fq12.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/src/fields/fq2.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/src/fields/fq6.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/src/fields/fr.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/src/fields/mod.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/ark-bls12-377/x/ark-bls12-377-0.6.0/src/fields/tests.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/py_ecc-8.0.0-py3-none-any.whl` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/__init__.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/py.typed` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/typing.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/utils.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/bls/__init__.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/bls/ciphersuites.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/bls/constants.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/bls/g2_primitives.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/bls/hash.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/bls/hash_to_curve.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/bls/point_compression.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/bls/typing.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/bls12_381/__init__.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/bls12_381/bls12_381_curve.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/bls12_381/bls12_381_pairing.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/bn128/__init__.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/bn128/bn128_curve.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/bn128/bn128_pairing.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/fields/__init__.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/fields/field_elements.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/fields/field_properties.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/fields/optimized_field_elements.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/optimized_bls12_381/__init__.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/optimized_bls12_381/constants.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/optimized_bls12_381/optimized_clear_cofactor.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/optimized_bls12_381/optimized_curve.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/optimized_bls12_381/optimized_pairing.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/optimized_bls12_381/optimized_swu.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/optimized_bn128/__init__.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/optimized_bn128/optimized_curve.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/optimized_bn128/optimized_pairing.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/secp256k1/__init__.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc/secp256k1/secp256k1.py` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc-8.0.0.dist-info/METADATA` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc-8.0.0.dist-info/WHEEL` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc-8.0.0.dist-info/top_level.txt` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc-8.0.0.dist-info/RECORD` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pyecc/x/py_ecc-8.0.0.dist-info/licenses/LICENSE` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pairing/x/pairing-0.23.0/.cargo_vcs_info.json` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pairing/x/pairing-0.23.0/.gitignore` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pairing/x/pairing-0.23.0/CHANGELOG.md` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pairing/x/pairing-0.23.0/COPYRIGHT` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pairing/x/pairing-0.23.0/Cargo.toml` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pairing/x/pairing-0.23.0/Cargo.toml.orig` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pairing/x/pairing-0.23.0/LICENSE-APACHE` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pairing/x/pairing-0.23.0/LICENSE-MIT` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pairing/x/pairing-0.23.0/README.md` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pairing/x/pairing-0.23.0/rust-toolchain` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pairing/x/pairing-0.23.0/.github/workflows/ci.yml` | WAIVED-ARCHIVE/REFERENCE (never compiled) |
| `third_party/pairing/x/pairing-0.23.0/src/lib.rs` | WAIVED-ARCHIVE/REFERENCE (never compiled) |

## UNBOUND — GATE FAILS UNTIL BOUND OR WAIVED IN LEDGER

| File | ??? |
|---|---|
| `hsma_backup.tar.gz` | ??? |
| `Whitepaper_HSMA___Core_Ultimate.pdf` | ??? |

cmake_minimum_required(VERSION 3.24)
project(hsma LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ARM64/Termux: prefer lld; fall back silently where unavailable.
include(CheckLinkerFlag)
check_linker_flag(CXX "-fuse-ld=lld" HAS_LLD)
if(HAS_LLD)
    add_link_options(-fuse-ld=lld)
endif()

# ---- The contract ---------------------------------------------------------
add_library(hsma_params INTERFACE)
target_include_directories(hsma_params INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(hsma_params INTERFACE cxx_std_20)
target_compile_options(hsma_params INTERFACE -Wall -Wextra -Wpedantic -Werror)

# ---- DEC-090 lint is part of EVERY build ----------------------------------
find_program(BASH_PROG bash REQUIRED)
add_custom_target(lint_dec090
    COMMAND ${BASH_PROG} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/check_no_fp.sh
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "DEC-090: enforcing float-free numeric core")
add_dependencies(hsma_params lint_dec090)

# ---- Identity probe (feeds the DEC-086 ledger bot) ------------------------
add_executable(params_probe src/params_probe.cpp)
target_link_libraries(params_probe PRIVATE hsma_params)

enable_testing()
add_test(NAME contract_identity COMMAND params_probe)

# ══ Step 2: generated constants + field/numeric kernels (DEC-102) ══
set(GEN_DIR ${CMAKE_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${GEN_DIR})

find_package(Python3 COMPONENTS Interpreter REQUIRED)

set(GEN_OUTPUTS
    ${GEN_DIR}/pallas_params_gen.hpp
    ${GEN_DIR}/vesta_params_gen.hpp
    ${GEN_DIR}/field_golden.hpp
    ${GEN_DIR}/rnte_golden.hpp)

set(GEN_OUTPUTS ${GEN_OUTPUTS}
    ${GEN_DIR}/poseidon_params_gen.hpp
    ${GEN_DIR}/domain_registry_gen.hpp
    ${GEN_DIR}/poseidon_golden.hpp)

add_custom_command(
    OUTPUT  ${GEN_OUTPUTS}
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/gen_run_new.py
            --out ${GEN_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/gen_run_new.py
    COMMENT "[gen] deriving Montgomery constants + golden vectors (DEC-102)"
    VERBATIM)
add_custom_target(hsma_generated DEPENDS ${GEN_OUTPUTS})

add_library(hsma_fp INTERFACE)
target_include_directories(hsma_fp INTERFACE ${GEN_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(hsma_fp INTERFACE hsma_params)   # env contracts
target_compile_features(hsma_fp INTERFACE cxx_std_20)
add_dependencies(hsma_fp hsma_generated)               # regeneration is forced

add_library(hsma_numcore INTERFACE)
target_include_directories(hsma_numcore INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(hsma_numcore INTERFACE hsma_params)

add_executable(test_step2 conformance/test_step2.cpp)
target_link_libraries(test_step2 PRIVATE hsma_fp hsma_numcore)
add_dependencies(test_step2 hsma_generated)
add_test(NAME step2_conformance COMMAND test_step2)

add_executable(test_step3 conformance/test_step3.cpp)
target_link_libraries(test_step3 PRIVATE hsma_fp hsma_numcore)
add_dependencies(test_step3 hsma_generated)
add_test(NAME step3_conformance COMMAND test_step3)

# ══ Step 4: state vault (DEC-111..113) ══
set(GEN_OUTPUTS ${GEN_OUTPUTS} ${CMAKE_BINARY_DIR}/generated/smt_golden.hpp)

add_library(hsma_smt INTERFACE)
target_include_directories(hsma_smt INTERFACE ${CMAKE_BINARY_DIR}/generated
    ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(hsma_smt INTERFACE hsma_fp hsma_params)

add_executable(test_step4 conformance/test_step4.cpp)
target_link_libraries(test_step4 PRIVATE hsma_smt)
add_dependencies(test_step4 hsma_generated)
add_test(NAME step4_conformance COMMAND test_step4)

# ══ Step 5: mempool & transaction gate (DEC-119..122) ══
add_executable(test_step5 conformance/test_step5.cpp)
target_link_libraries(test_step5 PRIVATE hsma_smt)
add_dependencies(test_step5 hsma_generated)
add_test(NAME step5_conformance COMMAND test_step5)



# ══ Step-5 diagnostic instrument (self-authenticating: prints VERDICT:) ══
add_executable(diag_step5 conformance/diag_step5.cpp)
target_link_libraries(diag_step5 PRIVATE hsma_smt)
add_dependencies(diag_step5 hsma_generated)

# ══ Step 6: MSSC automaton (DEC-136..139) ══
set(GEN_OUTPUTS ${GEN_OUTPUTS} ${GEN_DIR}/consensus_golden.hpp)

add_executable(diag_step6 conformance/diag_step6.cpp)
target_link_libraries(diag_step6 PRIVATE hsma_fp)
add_dependencies(diag_step6 hsma_generated)

add_executable(test_step6 conformance/test_step6.cpp)
target_link_libraries(test_step6 PRIVATE hsma_fp)
add_dependencies(test_step6 hsma_generated)
add_test(NAME step6_conformance COMMAND test_step6)

# == Step 7: threshold scalar module F_r (DEC-181..184) ==
add_executable(test_step7 conformance/test_step7.cpp)
target_include_directories(test_step7 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step7_conformance COMMAND test_step7)

# == Step 8: G1 promotion (DEC-185..188) ==
add_executable(test_step8 conformance/test_step8.cpp)
target_include_directories(test_step8 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step8_conformance COMMAND test_step8)

# == Step 9: threshold protocol layer (DEC-189..192) ==
add_executable(test_step9 conformance/test_step9.cpp)
target_include_directories(test_step9 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step9_conformance COMMAND test_step9)

# == Step 10: F_q2 + E twist (DEC-193..196) ==
add_executable(test_step10 conformance/test_step10.cpp)
target_include_directories(test_step10 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step10_conformance COMMAND test_step10)

# == Step 10-B: pairing layer (DEC-197..199) ==
add_executable(test_step10b conformance/test_step10b.cpp)
target_include_directories(test_step10b PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step10b_conformance COMMAND test_step10b)

# == Step 11: sim_beacon retirement (DEC-200) - values-only swap, no new target. ==
# == test_step6/diag_step6/test_step9 migrated to threshold::beacon; consensus  ==
# == goldens regenerated with HSM_BEACON_V1 (beacon feeds the sampler seed).  ==
# == Step 12: M2 order-bound shares (DEC-201..203) ==
add_executable(test_step12 conformance/test_step12.cpp)
target_include_directories(test_step12 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step12_conformance COMMAND test_step12)

# == Step 13: M2 production hardening (DEC-204..206) ==
add_executable(test_step13 conformance/test_step13.cpp)
target_include_directories(test_step13 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step13_conformance COMMAND test_step13)

# == Step 14: fold step family (DEC-207) ==
add_executable(test_step14 conformance/test_step14.cpp)
target_include_directories(test_step14 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step14_conformance COMMAND test_step14)

# == Step 15: CCS constraint layer (DEC-208) ==
add_executable(test_step15 conformance/test_step15.cpp)
target_include_directories(test_step15 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step15_conformance COMMAND test_step15)

# == Step 16: NIVC fold accumulator (DEC-209) ==
add_executable(test_step16 conformance/test_step16.cpp)
target_include_directories(test_step16 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step16_conformance COMMAND test_step16)

# == Step 17: epoch pipeline (DEC-210) ==
add_executable(test_step17 conformance/test_step17.cpp)
target_include_directories(test_step17 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step17_conformance COMMAND test_step17)

# == Step 18: G1 transport skeleton (DEC-211) ==
add_executable(test_step18 conformance/test_step18.cpp)
target_include_directories(test_step18 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step18_conformance COMMAND test_step18)

# == Step 19: sum-check engine (DEC-212) ==
add_executable(test_step19 conformance/test_step19.cpp)
target_include_directories(test_step19 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step19_conformance COMMAND test_step19)

# == Step 20: multilinear PCS (DEC-213) ==
add_executable(test_step20 conformance/test_step20.cpp)
target_include_directories(test_step20 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step20_conformance COMMAND test_step20)

# == Step 21: NIFS fold (DEC-214) ==
add_executable(test_step21 conformance/test_step21.cpp)
target_include_directories(test_step21 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step21_conformance COMMAND test_step21)

# == Step 22: light-client epoch-header certificate (DEC-215) ==
add_executable(test_step22 conformance/test_step22.cpp)
target_include_directories(test_step22 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step22_conformance COMMAND test_step22)

# == Step 23: phi0-phi7 end-to-end epoch (DEC-216) ==
add_executable(test_step23 conformance/test_step23.cpp)
target_include_directories(test_step23 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step23_conformance COMMAND test_step23)

# == Step 24: Vesta field twin (DEC-222) ==
add_executable(test_step24 conformance/test_step24.cpp)
target_include_directories(test_step24 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step24_conformance COMMAND test_step24)

# == Step 25: Vesta Poseidon (DEC-223) ==
add_executable(test_step25 conformance/test_step25.cpp)
target_include_directories(test_step25 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step25_conformance COMMAND test_step25)

# == Step 26: Vesta curve ops (DEC-224) ==
add_executable(test_step26 conformance/test_step26.cpp)
target_include_directories(test_step26 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step26_conformance COMMAND test_step26)

# == Step 27: CycleFold absorption (DEC-225) ==
add_executable(test_step27 conformance/test_step27.cpp)
target_include_directories(test_step27 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step27_conformance COMMAND test_step27)

# == Step 28: Pallas curve ops (DEC-226) ==
add_executable(test_step28 conformance/test_step28.cpp)
target_include_directories(test_step28 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step28_conformance COMMAND test_step28)

# == Step 29: Pedersen Layer 1 (DEC-227) ==
add_executable(test_step29 conformance/test_step29.cpp)
target_include_directories(test_step29 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step29_conformance COMMAND test_step29)

# == Step 30: WHIR-class wrap (DEC-228) ==
add_executable(test_step30 conformance/test_step30.cpp)
target_include_directories(test_step30 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step30_conformance COMMAND test_step30)

# == Step 31: HyperNova multifold core (DEC-229) ==
add_executable(test_step31 conformance/test_step31.cpp)
target_include_directories(test_step31 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step31_conformance COMMAND test_step31)

# == Step 32: Commitment folding (DEC-230) ==
add_executable(test_step32 conformance/test_step32.cpp)
target_include_directories(test_step32 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step32_conformance COMMAND test_step32)

# == Step 33: f_exec circuit (DEC-231) ==
add_executable(test_step33 conformance/test_step33.cpp)
target_include_directories(test_step33 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step33_conformance COMMAND test_step33)

# == Step 34: the epoch chain + pi_E (DEC-232) ==
add_executable(test_step34 conformance/test_step34.cpp)
target_include_directories(test_step34 PRIVATE "${CMAKE_SOURCE_DIR}/include" "${CMAKE_SOURCE_DIR}/build/generated")
add_test(NAME step34_conformance COMMAND test_step34)

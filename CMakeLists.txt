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
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/scripts/gen_constants.py
            --out ${GEN_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/scripts/gen_constants.py
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

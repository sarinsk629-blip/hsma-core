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

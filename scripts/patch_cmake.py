with open("CMakeLists.txt", "r") as f:
    c = f.read()

c = c.replace(
    '    ${GEN_DIR}/rnte_golden.hpp)',
    '    ${GEN_DIR}/rnte_golden.hpp)\n\nset(GEN_OUTPUTS ${GEN_OUTPUTS}\n    ${GEN_DIR}/poseidon_params_gen.hpp\n    ${GEN_DIR}/domain_registry_gen.hpp\n    ${GEN_DIR}/poseidon_golden.hpp)'
)

c += """
add_executable(test_step3 conformance/test_step3.cpp)
target_link_libraries(test_step3 PRIVATE hsma_fp hsma_numcore)
add_dependencies(test_step3 hsma_generated)
add_test(NAME step3_conformance COMMAND test_step3)
"""
with open("CMakeLists.txt", "w") as f:
    f.write(c)

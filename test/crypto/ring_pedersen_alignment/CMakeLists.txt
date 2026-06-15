add_executable(ring_pedersen_alignment_test
    tests.cpp
    ${PROJECT_SOURCE_DIR}/src/common/crypto/commitments/ring_pedersen.c
)

target_compile_options(ring_pedersen_alignment_test PRIVATE -Wall -Wextra)
target_link_libraries(ring_pedersen_alignment_test PRIVATE tests_main)

add_test(NAME ring_pedersen_alignment_test COMMAND ring_pedersen_alignment_test)

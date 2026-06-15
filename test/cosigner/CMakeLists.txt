list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(UUID REQUIRED)
find_package(Threads REQUIRED)

add_executable(cosigner_test
    ecdsa_offline_test.cpp
    ecdsa_online_test.cpp
    eddsa_offline_test.cpp
    eddsa_online_test.cpp
    bam_test.cpp
    setup_test.cpp
)

# Link the necessary libraries to the cosigner_test target
if(APPLE)
    target_link_libraries(cosigner_test PRIVATE tests_main cosigner Threads::Threads) # No UUID library on macOS
else()
    target_link_libraries(cosigner_test PRIVATE tests_main cosigner Threads::Threads UUID::UUID)
endif()

add_test(NAME cosigner_test COMMAND cosigner_test)

# High-level (cosigner-level) reproducer for the ring_pedersen misaligned-uint32
# access bug; standalone executable (it has its own main(), not a Catch test).
add_executable(align_repro align_repro.cpp)
target_compile_options(align_repro PRIVATE -Wall -Wextra)
target_include_directories(align_repro PRIVATE ${PROJECT_SOURCE_DIR}/src/common)
target_link_libraries(align_repro PRIVATE cosigner)
add_test(NAME align_repro COMMAND align_repro)

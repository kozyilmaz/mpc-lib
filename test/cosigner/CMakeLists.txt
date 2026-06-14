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

# Isolated single-file binary: it overrides global operator new/delete to count
# allocations, so it must not share a binary with the other cosigner tests.
# Demonstrates the leak/UB in ecdsa_preprocessing_data's destructor.
add_executable(cosigner_preprocessing_data_leak_test ecdsa_preprocessing_data_leak_test.cpp)
if(APPLE)
    target_link_libraries(cosigner_preprocessing_data_leak_test PRIVATE tests_main cosigner Threads::Threads)
else()
    target_link_libraries(cosigner_preprocessing_data_leak_test PRIVATE tests_main cosigner Threads::Threads UUID::UUID)
endif()
add_test(NAME cosigner_preprocessing_data_leak_test COMMAND cosigner_preprocessing_data_leak_test)

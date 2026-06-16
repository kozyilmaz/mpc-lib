add_executable(string_utils_test tests.cpp)

target_compile_options(string_utils_test PRIVATE -Wall -Wextra)
target_link_libraries(string_utils_test PRIVATE tests_main)

add_test(NAME string_utils_test COMMAND string_utils_test)

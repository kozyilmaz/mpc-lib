/*
 * container_cleaner empty-safety (include/utils/string_utils.h). The destructor
 * does OPENSSL_cleanse(&_secret[0], ...); on an empty std::vector &_secret[0] is
 * out-of-bounds operator[] (UB). Under -D_GLIBCXX_ASSERTIONS or -fsanitize=undefined
 * the empty case aborts against the buggy destructor and passes once it's empty-safe;
 * the non-empty case checks the wipe still zeroes the buffer.
 */
#include "utils/string_utils.h"

#include <tests/catch.hpp>

#include <string>
#include <vector>

using namespace fireblocks::common::utils;

TEST_CASE("container_cleaner is empty-safe", "[utils][container_cleaner]") {
    // Must destruct without out-of-bounds access; reaching here (no abort) is the signal.
    { byte_vector_t v; byte_vector_cleaner c(v); }
    { std::string  s; string_cleaner     c(s); }
    SUCCEED("empty cleaners destructed without out-of-bounds access");
}

TEST_CASE("container_cleaner wipes a non-empty buffer", "[utils][container_cleaner]") {
    byte_vector_t v{0x11, 0x22, 0x33, 0x44};
    { byte_vector_cleaner c(v); }
    REQUIRE(v == byte_vector_t(4, 0x00));        // contents zeroed, size unchanged

    std::string s = "secret";
    const size_t n = s.size();
    { string_cleaner c(s); }
    REQUIRE(s == std::string(n, '\0'));
}

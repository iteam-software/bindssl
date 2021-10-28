#include <sstream>
#include <gtest/gtest.h>
#include <ensure_ssl_binding.h>

TEST(strconv, binhex) {
    char* hash = "b89eaac7e61417341b710b727768294d0e6a277b";

    auto bytes = ensure_ssl_binding::strconv_hb(hash);
    auto actual = ensure_ssl_binding::strconv_bh(bytes);
    
    EXPECT_STREQ(actual.c_str(), hash);
}
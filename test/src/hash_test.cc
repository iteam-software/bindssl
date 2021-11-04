#include <convert.h>

#include <sstream>

#include <gtest/gtest.h>


TEST(strconv, binhex) {
  char* hash = "b89eaac7e61417341b710b727768294d0e6a277b";

  auto [bytes, bytes_succeeded] = bindssl::ConvertHexToBytes(hash);
  auto [actual, actual_succeeded] = bindssl::ConvertToHexString(bytes);
  
  EXPECT_TRUE(bytes_succeeded);
  EXPECT_TRUE(actual_succeeded);
  EXPECT_STREQ(actual.c_str(), hash);
}
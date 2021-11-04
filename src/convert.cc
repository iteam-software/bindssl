#include "convert.h"

#include <sstream>
#include <tuple>

bindssl::Result<std::wstring>
bindssl::ConvertToWString(const std::string& value) {
  std::wstring result;
  size_t resultsz = 0;
  errno_t error = 0;
  result.resize(value.length() + 1);
  if (mbstowcs_s(
      &resultsz, &result[0], result.length(), value.c_str(), _TRUNCATE) != 0) {
    return std::make_tuple(L"", false);
  }
  return std::make_tuple(result.c_str(), true);
}

bindssl::Result<std::vector<bindssl::Byte>>
bindssl::ConvertHexToBytes(const std::string& value) {
  size_t hashlen = value.length();
  std::vector<Byte> result(hashlen / 2, 0);
  for (size_t i = 0, j = 0; i < result.size(); ++i)
  {
      result[i] = (Byte)stoul(value.substr(j, 2), nullptr, 16);
      j += 2;
  }
  return std::make_tuple(result, true);
}

bindssl::Result<std::string>
bindssl::ConvertToHexString(const std::vector<bindssl::Byte>& value) {
  std::stringstream ss;
  for (size_t i = 0; i < value.size(); i++)
  {
      std::string buff(2, '\0');
      snprintf(&buff[0], 3, "%02x", value[i]);
      ss << buff;
  }
  return std::make_tuple(ss.str(), true);
}
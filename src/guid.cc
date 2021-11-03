#include "guid.h"

#include <tuple>

bindssl::Result<std::string>
bindssl::GuidToString(const bindssl::Guid& guid)
{
  std::string val{};
  int converted_bytes = sprintf_s(
    &val[0], 37, "%x-%x-%x-%x%x-%x%x%x%x%x%x",
    guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1],
    guid.Data4[2], guid.Data4[3], guid.Data4[4],
    guid.Data4[5], guid.Data4[6], guid.Data4[7]
  );

  return std::make_tuple(val, converted_bytes > 0);
}

bindssl::Result<bindssl::Guid>
bindssl::GuidFromString(const std::string& value)
{
  bindssl::Guid guid{};
  int converted_count = sscanf_s(
    value.c_str(),
    "%8x-%4hx-%4hx-%2hhx%2hhx-%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
    &guid.Data1, &guid.Data2, &guid.Data3, &guid.Data4[0], &guid.Data4[1],
    &guid.Data4[2], &guid.Data4[3], &guid.Data4[4],
    &guid.Data4[5], &guid.Data4[6], &guid.Data4[7]
  );

  return std::make_tuple(guid, converted_count > 0);
}

#ifndef GUID_H
#define GUID_H

#include "result.h"

#include <string>

#include <guiddef.h>

namespace bindssl
{

typedef GUID Guid;

Result<std::string> GuidToString(const Guid& guid);
Result<Guid> GuidFromString(const std::string& value);

} // namespace bindssl

#endif
#ifndef HASH_H
#define HASH_H

#include "primitives.h"
#include "result.h"

#include <string>
#include <vector>

namespace bindssl
{

Result<std::wstring> ConvertToWString(const std::string&);
Result<std::vector<Byte>> ConvertHexToBytes(const std:: string&);
Result<std::string> ConvertToHexString(const std::vector<Byte>&);

} // namespace bindssl


#endif
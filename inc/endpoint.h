#ifndef ENDPOINT_H
#define ENDPOINT_H

#include "platform.h"
#include "result.h"

#include <memory>
#include <string>

namespace bindssl
{

typedef SOCKADDR Endpoint;

Result<std::shared_ptr<Endpoint>> SockAddressFromString(
  const std::string& endpoint);

} // namespace bindssl

#endif

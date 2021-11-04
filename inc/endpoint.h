#ifndef ENDPOINT_H
#define ENDPOINT_H

#include "platform.h"
#include "result.h"

#include <memory>
#include <string>

namespace bindssl
{

typedef SOCKADDR Endpoint;

void ClearEndpointCache();
Result<std::shared_ptr<Endpoint>> SockAddressFromString(
  const std::string& endpoint);

} // namespace bindssl

#endif

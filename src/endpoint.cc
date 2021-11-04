#include "endpoint.h"
#include "platform.h"
#include "convert.h"

#include <memory>
#include <tuple>

bindssl::Result<std::shared_ptr<bindssl::Endpoint>>
bindssl::SockAddressFromString(const std::string& endpoint) {
  auto [endpoint_w, endpoint_w_success] = bindssl::ConvertToWString(endpoint);
  if (!endpoint_w_success) {
    return std::make_tuple(nullptr, false);
  }

  SOCKADDR_STORAGE storage{};
  LPSOCKADDR address = (LPSOCKADDR)&storage;
  int size = sizeof(storage);
  if (WSAStringToAddressW(
      (LPWSTR)endpoint_w.c_str(), AF_INET, NULL,
      address, &size) != NO_ERROR
  ) {
    return std::make_tuple(nullptr, false);
  }
  return std::make_tuple(std::make_shared<Endpoint>(*address), true);
}
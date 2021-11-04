#include "endpoint.h"
#include "platform.h"
#include "convert.h"

#include <map>
#include <memory>
#include <tuple>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"

auto console = spdlog::stdout_color_mt("Endpoint");
auto cache = std::map<std::string, std::shared_ptr<bindssl::Endpoint>>{};

void bindssl::ClearEndpointCache() {
  cache.clear();
}

bindssl::Result<std::shared_ptr<bindssl::Endpoint>>
bindssl::SockAddressFromString(const std::string& endpoint) {
  if (cache.count(endpoint) > 0) {
    return std::make_tuple(cache[endpoint], true);
  }

  console->trace("Converting {} into socket address", endpoint);
  
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
    console->warn("Unable to convert endpoint into socket address");
    return std::make_tuple(nullptr, false);
  }

  cache.insert({endpoint, std::make_shared<Endpoint>(*address)});
  return std::make_tuple(cache[endpoint], true);
}
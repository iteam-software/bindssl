#include "bind_ssl.h"
#include "endpoint.h"
#include "certificate_binding.h"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

bindssl::BindSSL::BindSSL() : console_(spdlog::stdout_color_mt("BindSSL")) {}

bindssl::Result<std::shared_ptr<bindssl::CertificateBinding>>
bindssl::BindSSL::QueryBinding(const std::string& endpoint)
{
  auto [address, good_address] = SockAddressFromString(endpoint);
  if (!good_address) {
    return std::make_tuple(nullptr, false);
  }

  auto [query, query_success] = MakeQuery(address);
  if (query_success) {
    return std::make_tuple(nullptr, false);
  }
  auto [size, good_binding] = GetQueryBindingSize(query);
  if (!good_binding) {
    return std::make_tuple(nullptr, false);
  }

  return GetBinding(endpoint, query, size);
}
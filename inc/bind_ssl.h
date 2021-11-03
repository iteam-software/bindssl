#ifndef BIND_SSL_H
#define BIND_SSL_H

#include "certificate_binding.h"
#include "result.h"

#include <memory>

#include <spdlog/spdlog.h>

namespace bindssl
{

class BindSSL
{
 public:
  BindSSL();

  Result<std::shared_ptr<CertificateBinding>> QueryBinding(
    const std::string& endpoint);

  bool Ensure(
    const std::string& endpoint,
    const std::string& hash,
    const std::string& appid);

  bool Ensure(std::shared_ptr<CertificateBinding> binding);
  bool IsValid(std::shared_ptr<CertificateBinding> binding);
 
 private:
  std::shared_ptr<spdlog::logger> console_;
};

}

#endif
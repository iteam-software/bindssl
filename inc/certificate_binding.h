#ifndef CERTIFICATE_BINDING_H
#define CERTIFICATE_BINDING_H

#include "guid.h"
#include "platform.h"
#include "endpoint.h"
#include "result.h"
#include "primitives.h"
#include "certificate_binding_info.h"

#include <memory>
#include <string>
#include <vector>

#include <spdlog/spdlog.h>

namespace bindssl
{

typedef ::HTTP_SERVICE_CONFIG_SSL_QUERY BindingQuery;
typedef ::HTTP_SERVICE_CONFIG_SSL_SET BindingSet;

class CertificateBinding {
 public:
  CertificateBinding(
      const std::string& endpoint,
      const std::string& hash,
      const std::string& appid);
  ~CertificateBinding();

  bool CheckBinding();
  bool Rebind();
 private:
  CertificateBindingInfo          info_;
  std::shared_ptr<spdlog::logger> logger_;
  bool                            platform_healthy_;
};

} // bindssl

#endif

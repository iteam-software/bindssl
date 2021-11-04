#ifndef CERTIFICATE_BINDING_INFO_H
#define CERTIFICATE_BINDING_INFO_H

#include "guid.h"
#include "primitives.h"

#include <memory>
#include <string>
#include <vector>

namespace bindssl
{

class CertificateBindingInfo {
 public:
  std::string       endpoint;
  std::string       hash;
  std::vector<Byte> hash_bytes;
  std::string       app_id;
  Guid              app_id_guid;
  bool              is_valid;

  CertificateBindingInfo() : is_valid(false) {}
  CertificateBindingInfo(const std::string& endpoint,
      const std::string& hash, const std::string& appid);
};

} // namespace bindssl

#endif
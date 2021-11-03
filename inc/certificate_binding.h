#ifndef CERTIFICATE_BINDING_H
#define CERTIFICATE_BINDING_H

#include "guid.h"
#include "platform.h"
#include "endpoint.h"
#include "result.h"
#include "primitives.h"

#include <memory>
#include <string>
#include <vector>

namespace bindssl
{

typedef ::HTTP_SERVICE_CONFIG_SSL_QUERY BindingQuery;
typedef ::HTTP_SERVICE_CONFIG_SSL_SET BindingSet;

class CertificateBinding {
 public:
  std::string       endpoint;
  std::string       hash;
  std::vector<Byte> hash_bytes;
  std::string       app_id;
  Guid              app_id_guid;
  CertificateBinding() {};
  CertificateBinding(const BindingSet& rhs);
  CertificateBinding(std::shared_ptr<BindingSet> set)
      : CertificateBinding(*set.get()) {}
};

Result<BindingQuery> MakeQuery(std::shared_ptr<Endpoint> address);

Result<BindingSet> MakeNewBindingSet(
    std::string address,
    std::string hash,
    std::string guid);

Result<ULong> GetQueryBindingSize(const BindingQuery& query);

Result<std::shared_ptr<CertificateBinding>> GetBinding(
    const std::string endpoint,
    const BindingQuery& query,
    ULong size);

Result<std::shared_ptr<CertificateBinding>> SetBinding(
    const std::string& endpoint,
    std::shared_ptr<bindssl::BindingSet> query);

} // bindssl

#endif

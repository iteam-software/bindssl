#include "certificate_binding.h"
#include "endpoint.h"
#include "guid.h"
#include "hash.h"

#include <memory>
#include <tuple>
#include <vector>

bindssl::CertificateBinding::CertificateBinding(
    const bindssl::BindingSet& data) {
  app_id_guid = data.ParamDesc.AppId;
  hash_bytes = std::vector<Byte>(
      (int)data.ParamDesc.pSslHash,
      (int)data.ParamDesc.pSslHash + (int)data.ParamDesc.SslHashLength);
  
  auto [hash, hash_success] = ConvertToHexString(hash_bytes);
  if (hash_success) {
    hash = hash;
  }
  
  auto [guid, guid_success] = GuidToString(data.ParamDesc.AppId);
  if (guid_success) {
    app_id = guid;
  }
}

bindssl::Result<bindssl::BindingQuery>
MakeQuery(std::shared_ptr<bindssl::Endpoint> address) {
  return std::make_tuple(bindssl::BindingQuery{
    HttpServiceConfigQueryExact,
    HTTP_SERVICE_CONFIG_SSL_KEY{
      (LPSOCKADDR)address.get()
    }
  }, true);
}

bindssl::Result<bindssl::BindingSet>
MakeNewBindingSet(std::string address, std::string hash_s, std::string guid_s) {
  bindssl::BindingSet set{};
  auto [endpoint, endpoint_success] = bindssl::SockAddressFromString(address);
  if (!endpoint_success) {
    return std::make_tuple(std::move(set), false);
  }

  auto [hashbytes, hashbytes_success] = bindssl::ConvertHexToBytes(hash_s);
  if (!hashbytes_success) {
    return std::make_tuple(std::move(set), false);
  }

  auto [guid, guid_success] = bindssl::GuidFromString(guid_s);
  if (!guid_success) {
    return std::make_tuple(std::move(set), false);
  }

  set.KeyDesc.pIpPort = (LPSOCKADDR)endpoint.get();
  set.ParamDesc.AppId = guid;
  set.ParamDesc.pSslHash = &hashbytes[0];
  set.ParamDesc.SslHashLength = hashbytes.size();
  set.ParamDesc.pSslCertStoreName = L"My";

  return std::make_tuple(std::move(set), true);
}

bindssl::Result<bindssl::ULong>
bindssl::GetQueryBindingSize(const bindssl::BindingQuery& query) {
  ULong size{0};
  HRESULT hr = HttpQueryServiceConfiguration(
      NULL, HttpServiceConfigSSLCertInfo,
      (void*)&query, sizeof(query), nullptr,
      size, &size, NULL);

  return std::make_tuple(size, hr == ERROR_INSUFFICIENT_BUFFER);
}

bindssl::Result<std::shared_ptr<bindssl::CertificateBinding>>
bindssl::GetBinding(const std::string endpoint,
    const bindssl::BindingQuery& query,
    bindssl::ULong size) {
  bindssl::BindingSet data{};
  HRESULT hr = HttpQueryServiceConfiguration(
      NULL, HttpServiceConfigSSLCertInfo,
      (void*)&query, sizeof(query), &data,
      size, &size, NULL);
  if (hr != NO_ERROR) {
    return std::make_tuple(nullptr, false);  
  }

  auto binding = std::make_shared<CertificateBinding>(CertificateBinding(data));
  binding->endpoint = endpoint;
  return std::make_tuple(binding, true);
}

bindssl::Result<std::shared_ptr<bindssl::CertificateBinding>>
bindssl::SetBinding(
    const std::string& endpoint,
    const bindssl::BindingSet& set) {
  HRESULT hr = HttpSetServiceConfiguration(
    NULL, HttpServiceConfigSSLCertInfo, (PVOID)&set, sizeof(set), NULL);
  if (hr == NO_ERROR) {
    return std::make_tuple(
        std::make_shared<CertificateBinding>(CertificateBinding(set)), true);
  }
  return std::make_tuple(nullptr, false);
}
#include "certificate_binding.h"
#include "endpoint.h"
#include "guid.h"
#include "convert.h"
#include "platform.h"

#include <memory>
#include <tuple>
#include <vector>

#include "spdlog/sinks/stdout_color_sinks.h"

bindssl::CertificateBinding::CertificateBinding(
    const std::string& endpoint,
    const std::string& hash,
    const std::string& appid) {
  info_ = CertificateBindingInfo(endpoint, hash, appid);
  logger_ = spdlog::stdout_color_mt("CertificateBinding");
  platform_healthy_ = true;
  platform_data_ = NULL;

  if (::HttpInitialize(
      HTTPAPI_VERSION_1, HTTP_INITIALIZE_CONFIG, NULL) != NO_ERROR) {
    logger_->error("httpapi initialization failed");
    platform_healthy_ = false;
  }

  WSADATA data{};
  if (platform_healthy_ && ::WSAStartup(MAKEWORD(2, 2), &data) != NO_ERROR) {
    logger_->error("winsock initialization failed");
    platform_healthy_ = false;
  }
}

bindssl::CertificateBinding::~CertificateBinding() {
  bindssl::ClearEndpointCache();
  WSACleanup();
  HttpTerminate(HTTP_INITIALIZE_CONFIG, NULL);
  if (platform_data_) {
    LocalFree(platform_data_);
  }
}

bool bindssl::CertificateBinding::CheckBinding() {
  if (!info_.is_valid || !platform_healthy_) {
    return false;
  }

  auto [address, address_success] = bindssl::SockAddressFromString(
    info_.endpoint);
  if (!address_success) {
    return false;
  }

  logger_->trace("Querying httpapi for certificate binding");
  auto query = bindssl::BindingQuery{
    ::HttpServiceConfigQueryExact,
    ::HTTP_SERVICE_CONFIG_SSL_KEY{
      (::LPSOCKADDR)address.get()
    }
  };

  bindssl::ULong size{0};
  if (::HttpQueryServiceConfiguration(
      NULL, HttpServiceConfigSSLCertInfo,
      (void*)&query, sizeof(query), nullptr,
      size, &size, NULL) != ERROR_INSUFFICIENT_BUFFER) {
    logger_->warn("Unable to query httpapi for binding size");
    return false;
  }

  HLOCAL platform_data_ = LocalAlloc(LMEM_FIXED, size);
  if (::HttpQueryServiceConfiguration(
      NULL, HttpServiceConfigSSLCertInfo,
      (void*)&query, sizeof(query), platform_data_,
      size, NULL, NULL) != NO_ERROR) {
    logger_->warn("Unable to query httpapi for binding info");
    return false;
  }

  auto set = (PHTTP_SERVICE_CONFIG_SSL_SET)platform_data_;
  auto hash_bytes = std::vector<bindssl::Byte>(
      (Byte*)set->ParamDesc.pSslHash,
      (Byte*)set->ParamDesc.pSslHash + (int)set->ParamDesc.SslHashLength);

  logger_->trace("Validating hash and appid against binding");
  return info_.hash_bytes == hash_bytes &&
      info_.app_id_guid == set->ParamDesc.AppId;
}

bool bindssl::CertificateBinding::Rebind() {
  if (!info_.is_valid || !platform_healthy_) {
    return false;
  }

  auto [address, address_success] = bindssl::SockAddressFromString(
    info_.endpoint);
  if (!address_success) {
    return false;
  }

  logger_->trace("Attempting to configure new binding");

  bindssl::BindingSet set{};
  set.KeyDesc.pIpPort = (LPSOCKADDR)address.get();
  set.ParamDesc.AppId = info_.app_id_guid;
  set.ParamDesc.pSslHash = (PVOID)&info_.hash_bytes[0];
  set.ParamDesc.SslHashLength = info_.hash_bytes.size();
  set.ParamDesc.pSslCertStoreName = L"My";

  HRESULT hr = ::HttpSetServiceConfiguration(
      NULL, HttpServiceConfigSSLCertInfo, &set,
      sizeof(set), NULL);
  if (hr != NO_ERROR) {
    logger_->warn("Failed to configure binding, httpapi error {}", hr);
    return false;
  }

  return true;
}

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

  if (::HttpInitialize(
      HTTPAPI_VERSION_1, HTTP_INITIALIZE_CONFIG, NULL) != NO_ERROR) {
    logger_->trace("httpapi initialization failed");
    platform_healthy_ = false;
  }

  WSADATA data{};
  if (platform_healthy_ && ::WSAStartup(MAKEWORD(2, 2), &data) != NO_ERROR) {
    logger_->trace("winsock initialization failed");
    platform_healthy_ = false;
  }
}

bindssl::CertificateBinding::~CertificateBinding() {
  WSACleanup();
  HttpTerminate(HTTP_INITIALIZE_CONFIG, NULL);
}

bool bindssl::CertificateBinding::CheckBinding() {
  if (!info_.is_valid || !platform_healthy_) {
    return false;
  }

  auto [address, address_success] = bindssl::SockAddressFromString(
    info_.endpoint);
  if (!address_success) {
    logger_->trace("Unable to convert endpoint to addressable socket");
    return false;
  }

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
    logger_->trace("Unable to query httpapi for binding size");
    return false;
  }

  ::HTTP_SERVICE_CONFIG_SSL_SET data{};
  if (::HttpQueryServiceConfiguration(
      NULL, HttpServiceConfigSSLCertInfo,
      (void*)&query, sizeof(query), &data,
      size, NULL, NULL) != NO_ERROR) {
    logger_->trace("Unable to query httpapi for binding info");
    return false;
  }

  auto hash_bytes = std::vector<bindssl::Byte>(
      (Byte*)data.ParamDesc.pSslHash,
      (Byte*)data.ParamDesc.pSslHash + (int)data.ParamDesc.SslHashLength);  

  return info_.hash_bytes == hash_bytes &&
      info_.app_id_guid == data.ParamDesc.AppId;
}

bool bindssl::CertificateBinding::Rebind() {
  if (!info_.is_valid || !platform_healthy_) {
    return false;
  }

  auto [address, address_success] = bindssl::SockAddressFromString(
    info_.endpoint);
  if (!address_success) {
    logger_->trace("Unable to convert endpoint to addressable socket");
    return false;
  }

  bindssl::BindingSet set{};
  set.KeyDesc.pIpPort = (LPSOCKADDR)address.get();
  set.ParamDesc.AppId = info_.app_id_guid;
  set.ParamDesc.pSslHash = (PVOID)&info_.hash_bytes[0];
  set.ParamDesc.SslHashLength = info_.hash_bytes.size();
  set.ParamDesc.pSslCertStoreName = L"My";

  return HttpSetServiceConfiguration(
      NULL, HttpServiceConfigSSLCertInfo, (PVOID)&set,
      sizeof(set), NULL) == NO_ERROR;
}

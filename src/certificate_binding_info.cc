#include "certificate_binding_info.h"
#include "convert.h"
#include "guid.h"

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

bindssl::CertificateBindingInfo::CertificateBindingInfo(  
    const std::string& endpoint,
    const std::string& hash,
    const std::string& appid) {
  this->endpoint = endpoint;
  this->hash = hash;
  this->app_id = appid;

  auto console = spdlog::stdout_color_mt("CertificateBindingInfo");
  auto [guid, guid_success] = bindssl::GuidFromString(appid);
  if (!guid_success) {
    console->trace("invalid guid");
    is_valid = false;
  } else {
    app_id_guid = guid;
  }

  auto [hash_bytes, hash_bytes_success] = bindssl::ConvertHexToBytes(hash);
  if (!hash_bytes_success) {
    console->trace("invalid hash");
    is_valid = false;
  } else {
    this->hash_bytes = hash_bytes;
  }
}
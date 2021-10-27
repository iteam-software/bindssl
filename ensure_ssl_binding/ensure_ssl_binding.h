#pragma once

#include <iostream>
#include <string>
#include <tuple>
#include <vector>

// Platform
#if WIN32
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <http.h>
#endif

// 3rd-party libs
#include "CLI11.hpp"
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"

namespace ensure_ssl_binding {

const HTTPAPI_VERSION kHttpAPIVersion = HTTPAPI_VERSION_1;

class CertificateBinding {
public:
    CertificateBinding(std::string endpoint);

    #if WIN32
    void bindquery(PHTTP_SERVICE_CONFIG_SSL_SET data);
    std::shared_ptr<HTTP_SERVICE_CONFIG_SSL_SET> data();
    #endif

    std::string hash() const;
    std::string appid() const;
    
    bool ensure(std::string appid, std::string hash);
    bool is_valid() const;

private:
    std::string m_hash;
    std::string m_appid;
    std::string m_endpoint;
    bool m_valid{false};
    
    #if WIN32
    std::shared_ptr<HTTP_SERVICE_CONFIG_SSL_SET> m_data{nullptr};
    #endif
};

/// <summary>
/// Query the endpoint for the SSL binding.
/// </summary>
/// <param name="endpoint">The endpoint to query</param>
/// <returns>A tuple containing the appid and hash and success flag</returns>
std::shared_ptr<CertificateBinding> query_binding(std::string endpoint);

/// <summary>
/// Set the secure binding
/// </summary>
/// <param name="endpoint">The endpoint to query</param>
/// <param name="appid">The appid guid to bind</param>
/// <param name="hash">The hash of the certificate to bind</param>
/// <returns>Returns zero for success and non-zero otherwise.</returns>
int set_binding(std::string endpoint, std::string appid, std::string hash);

/// <summary>
/// Converts string to wstring
/// </summary>
/// <param name="value">The string to convert</param>
/// <returns>A tuple containing the converted string and a success flag</returns>
std::tuple<std::wstring, bool> strconv_w(std::string value);

/// <summary>
/// Converts a hex string to a byte array.
/// </summary>
/// <param name="value">The string to convert</param>
/// <returns>A std::vector<unsigned char> containing the converted data</returns>
std::vector<unsigned char> strconv_hb(std::string value);

/// <summary>
/// Performs initialization logic for the platform.
/// </summary>
/// <returns>True if initalization was successfull</returns>
bool init_platform();

/// <summary>
/// Performs cleanup logic for the platform.
/// <summary>
void cleanup_platform();

} // namespace ensure_ssl_binding

int main(int argc, char** argv);
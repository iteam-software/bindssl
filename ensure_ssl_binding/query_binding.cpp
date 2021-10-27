#include <memory>

#include "ensure_ssl_binding.h"

using namespace std;
using namespace ensure_ssl_binding;

shared_ptr<CertificateBinding> ensure_ssl_binding::query_binding(string endpoint)
{
    auto console = spdlog::stdout_color_mt("query_binding");
    auto binding = make_shared<CertificateBinding>(
        CertificateBinding(endpoint)
    );

    #if !WIN32
    
    console->warn("This feature is only available on the Windows platform");

    #else
    
    HRESULT hr;
    DWORD native, returnsz = 0;
    HTTP_SERVICE_CONFIG_SSL_QUERY queryinput{};
    HLOCAL p_output = NULL;
    SOCKADDR_STORAGE endpoint_stor{};

    // Configure the queryinput for our binding query
    queryinput.QueryDesc = HttpServiceConfigQueryExact;
    queryinput.KeyDesc.pIpPort = (LPSOCKADDR)&endpoint_stor;

    auto [w_endpoint, success] = strconv(endpoint);
    if (!success)
    {
        return binding;
    }
    
    int storsz = sizeof(endpoint_stor);
    if ((hr = WSAStringToAddressW(
        (LPWSTR)w_endpoint.c_str(),
        AF_INET,
        NULL,
        queryinput.KeyDesc.pIpPort,
        &storsz
    )) != NO_ERROR)
    {
        native = WSAGetLastError();
        console->error(
            "Invalid endpoint provided {} - WSAError {}, please correct and try again",
            endpoint,
            native
        );
      
      return binding;
    }

    // Since our returnsz is currently set to 0, this first invocation will tell us how must memory
    // to allocate for the output data.
    hr = HttpQueryServiceConfiguration(
        NULL,
        HttpServiceConfigSSLCertInfo,
        &queryinput,
        sizeof(queryinput),
        p_output,
        returnsz,
        &returnsz,
        NULL
    );

    // This error is actually indicative of the success path and requires another invocation to 
    // load the certificate data.
    if (hr == ERROR_INSUFFICIENT_BUFFER && returnsz > 0)
    {
        p_output = LocalAlloc(LMEM_FIXED, returnsz);
        if (!p_output)
        {
            console->error("Not enough memory available for query");
            return binding;
        }

        hr = HttpQueryServiceConfiguration(
            NULL,
            HttpServiceConfigSSLCertInfo,
            &queryinput,
            sizeof(queryinput),
            p_output,
            returnsz,
            &returnsz,
            NULL
        );
    }


    auto data = (PHTTP_SERVICE_CONFIG_SSL_SET)p_output;
    switch (hr)
    {
        case NO_ERROR:
        console->trace("Binding found for endpoint {}", endpoint);
        if (!p_output)
        {
            console->error("HttpQueryServiceConfiguration succeeded but data is unavailable");
            return binding;
        }

        // We expect data to be loaded and can act on it.
        binding->bindquery(data);
        
        // Trace cert info
        console->trace("Binding AppId: {}", binding->appid());
        console->trace("Binding Certificate Hash: {}", binding->hash());
        
        break;
      
        default:
        console->error("HttpQueryServiceConfiguration failed with error {}", hr);
    }

    #endif

    return binding;
}
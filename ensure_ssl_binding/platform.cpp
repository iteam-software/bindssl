#include "ensure_ssl_binding.h"

bool ensure_ssl_binding::init_platform()
{
    auto console = spdlog::stdout_color_mt("init_platform");
    HRESULT hr;
    int native;

    if ((hr = HttpInitialize(kHttpAPIVersion, HTTP_INITIALIZE_CONFIG, NULL)) != NO_ERROR)
    {
        console->error("HttpInitialize failed with {}", hr);
        return false;
    }

    // Unfortunately we need to use winsock, so setup is required
    WSADATA data{};
    if ((hr = WSAStartup(MAKEWORD(2, 2), &data)) != NO_ERROR)
    {
        native = WSAGetLastError();
        console->error("WSAStartup failed with {}", native);
        return false;
    }

    return true;
}

void ensure_ssl_binding::cleanup_platform()
{
    WSACleanup();
    HttpTerminate(HTTP_INITIALIZE_CONFIG, NULL);
}
#include "ensure_ssl_binding.h"

using namespace std;

int ensure_ssl_binding::set_binding(string endpoint, string appid, string hash)
{
  auto console = spdlog::stdout_color_mt("set_binding");

  HTTP_SERVICE_CONFIG_SSL_SET setinfo{};


  console->error("This feature is not implemented");
  return -1;
}
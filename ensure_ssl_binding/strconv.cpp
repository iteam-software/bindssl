
#include <codecvt>
#include <locale>

#include "ensure_ssl_binding.h"

using namespace std;

tuple<wstring, bool> ensure_ssl_binding::strconv(string value)
{
    auto console = spdlog::stdout_color_mt("strconv");

    wstring result;
    size_t resultsz = 0;
    errno_t error = 0;
    bool invoking = true;

    result.resize(value.length() + 1);
    if ((error = mbstowcs_s(&resultsz, &result[0], result.length(), value.c_str(), _TRUNCATE)) != 0)
    {
        console->error("Failed to convert with code {}", error);
        return make_tuple<wstring, bool>(L"", false);
    }

    return make_tuple<wstring, bool>(result.c_str(), true);
}
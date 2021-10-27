
#include <codecvt>
#include <locale>

#include "ensure_ssl_binding.h"

using namespace std;

tuple<wstring, bool> ensure_ssl_binding::strconv_w(string value)
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

vector<unsigned char> ensure_ssl_binding::strconv_hb(string value)
{
    size_t hashlen = value.length();
    vector<unsigned char> result(hashlen / 2, 0);

    for (size_t i = 0, j = 0; i < result.size() && j < hashlen;)
    {
        result[i] = ((value[j] << 4) & 0xF0 | (value[j+1] & 0x0F));
        j += 2;
        i ++;
    }

    return result;
}
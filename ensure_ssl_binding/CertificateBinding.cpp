#include <sstream>

#include "ensure_ssl_binding.h"

using namespace std;
using namespace ensure_ssl_binding;

CertificateBinding::CertificateBinding(string endpoint) : m_endpoint(endpoint) { }

#if WIN32

void CertificateBinding::bindquery(PHTTP_SERVICE_CONFIG_SSL_SET data)
{
    this->m_appid = string();
    this->m_appid.resize(36);
    this->m_data = shared_ptr<HTTP_SERVICE_CONFIG_SSL_SET>(data, LocalFree);
    this->m_valid = true; // Optimistic initialization

    if (snprintf(
        &this->m_appid[0],
        37,
        "%x-%x-%x-%x%x-%x%x%x%x%x%x",
        data->ParamDesc.AppId.Data1,
        data->ParamDesc.AppId.Data2,
        data->ParamDesc.AppId.Data3,
        data->ParamDesc.AppId.Data4[0], data->ParamDesc.AppId.Data4[1],
        data->ParamDesc.AppId.Data4[2], data->ParamDesc.AppId.Data4[3],
        data->ParamDesc.AppId.Data4[4], data->ParamDesc.AppId.Data4[5],
        data->ParamDesc.AppId.Data4[6], data->ParamDesc.AppId.Data4[7]
    ) < 0) {
        this->m_valid = false;
    }

    stringstream ss;
    PUCHAR p_hash = (PUCHAR)data->ParamDesc.pSslHash;
    for (size_t i = 0; i < data->ParamDesc.SslHashLength; i++)
    {
        string buff(2, '\0');
        snprintf(&buff[0], 3, "%02x", p_hash[i]);
        ss << buff;
    }
    
    this->m_hash = ss.str();
}

shared_ptr<HTTP_SERVICE_CONFIG_SSL_SET> CertificateBinding::data()
{
    return this->m_data;
}

#endif // WIN32

string CertificateBinding::hash() const
{
    return this->m_hash;
}

string CertificateBinding::appid() const
{
    return this->m_appid;
}

bool CertificateBinding::ensure(string appid, string hash)
{
    vector<unsigned char> newhash;

    if (!this->m_valid)
    {
        // We never bound to a valid query -- repair is not supported for this
        // scenario, yet.
        return false;
    }

    if (this->m_appid == appid && this->m_hash == hash)
    {
        return true;
    }

    #if WIN32

    HRESULT hr;

    // We must attempt to rebind.
    if (this->m_hash != hash)
    {
        newhash = strconv_hb(hash);
        this->m_data->ParamDesc.SslHashLength = newhash.size();
        this->m_data->ParamDesc.pSslHash = &newhash[0];
    }

    if (this->m_appid != appid)
    {
        GUID guid{};
        if (sscanf_s(
            appid.c_str(),
            "%8x-%4hx-%4hx-%2hhx%2hhx-%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
            &guid.Data1,
            &guid.Data2,
            &guid.Data3,
            &guid.Data4[0], &guid.Data4[1],
            &guid.Data4[2], &guid.Data4[3],
            &guid.Data4[4], &guid.Data4[5],
            &guid.Data4[6], &guid.Data4[7]
        ) != 11)
        {
            this->m_valid = false;
            return false;
        }

        this->m_data->ParamDesc.AppId = guid;
    }

    this->m_data->ParamDesc.pSslCertStoreName = L"My";
    hr = HttpSetServiceConfiguration(
        NULL,
        HttpServiceConfigSSLCertInfo,
        this->m_data.get(),
        sizeof(*this->m_data),
        NULL
    );

    return hr == NO_ERROR;

    #else

    return false;

    #endif
}

bool CertificateBinding::is_valid() const
{
    return this->m_valid;
}

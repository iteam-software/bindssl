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
    return true;
}

bool CertificateBinding::is_valid() const
{
    return this->m_valid;
}

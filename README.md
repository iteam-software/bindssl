# bindssl

bindssl ensures a http binding exists given an endpoint, hash and appid.

## Usage
```
> ./bindssl.exe --endpoint 0.0.0.0:443 --hash e635112919bdf5ca852723559d8d18813ae73ecd --appid 214124cd-d05b-4309-9af9-9caa44b2b74a -v trace
```

Example output:
```
[2021-11-04 09:12:05.150] [Endpoint] [trace] Converting 0.0.0.0:443 into socket address
[2021-11-04 09:12:05.151] [CertificateBinding] [trace] Querying httpapi for certificate binding
[2021-11-04 09:12:05.151] [CertificateBinding] [warning] Unable to query httpapi for binding size
[2021-11-04 09:12:05.151] [CertificateBinding] [trace] Attempting to configure new binding
[2021-11-04 09:12:05.160] [App] [trace] Binding is unhealthy, attempting to repair
[2021-11-04 09:12:05.160] [App] [info] Rebind is healthy
```

Options:
```
-h,--help                   Print this help message and exit
-e,--endpoint TEXT REQUIRED The endpoint to check
-H,--hash TEXT REQUIRED     The certificate hash to check
-a,--appid TEXT REQUIRED    The appid to bind
-v,--verbosity ENUM:value in {error->4,trace->0,warning->3} OR {4,0,3}
                            Log level
```

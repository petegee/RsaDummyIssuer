using System.Security.Cryptography.X509Certificates;
using RsaThreeDeeSecure.Extensions;

namespace RsaDummyIssuer.Data
{
    public class RsaSigningCert
    {
        public static X509Certificate2 GetX509Certificate2()
            => new X509Certificate2(Cert.PemCertToByteArray());
        
        public const string Cert =
@"-----BEGIN CERTIFICATE-----
MIIJOzCCCCOgAwIBAgICECIwDQYJKoZIhvcNAQELBQAwXjELMAkGA1UEBhMCSUwx
CzAJBgNVBAgMAk5BMQwwCgYDVQQKDANSU0ExFTATBgNVBAsMDDNEU2VjdXJlIDIu
MDEdMBsGA1UEAwwUcnNhLmludGVybWlkaWF0ZS5jb20wHhcNMTkwMzMxMDcxNzI2
WhcNMjkwMzI4MDcxNzI2WjBvMQswCQYDVQQGEwJJTDEQMA4GA1UECBMHVW5rbm93
bjESMBAGA1UEBxMJSGVyemlsaXlhMQwwCgYDVQQKEwNSU0ExETAPBgNVBAsTCDNE
U2VjdXJlMRkwFwYDVQQDDBBjbGllbnRfc2lnbmF0dXJlMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEAql7+8++NhDK0cqVvVyE5wQaX6kGDsLMN6vw5SIGt
qFfiRzMV+mvwf/sQlBHrKfgeX43NauYqYZ2jIjEtK8ixf4J5tKRjXV+E3ccKX03z
+CV5tgP3TCuOuvCE/1yx8nTeXQnuaWERM7DtF+/lZzloWRvWq7kv49WuQhrvMIMs
/et8ZR5/bcdPpZwrp/6nxNDoohrG65MGwN9mgnNAKwlqpxrRsRC/cZAbGJX3IuhQ
r7If/CTJKP3Qnpe4tpIqV6ASgIStHBhw0P/6ltCDVDgG+E9x2GDHGWyqDkCgy65i
HfiBjgvtnwdOiKuvzpZimnyF87l/c0/X7/zbPsH1mW3ubQIDAQABo4IF8DCCBeww
ggUiBgNVHREEggUZMIIFFYIgd3d3LmxpbnV4cmQ0MDAuaHpsYWIubGFiLmVtYy5j
b22CHGxpbnV4cmQ0MDAuaHpsYWIubGFiLmVtYy5jb22CCmxpbnV4cmQ0MDCCIHd3
dy5saW51eHJkMzAwLmh6bGFiLmxhYi5lbWMuY29tghxsaW51eHJkMzAwLmh6bGFi
LmxhYi5lbWMuY29tggpsaW51eHJkMzAwgiB3d3cubGludXhwczQyMC5oemxhYi5s
YWIuZW1jLmNvbYIcbGludXhwczQyMC5oemxhYi5sYWIuZW1jLmNvbYIKbGludXhw
czQyMIIgd3d3LmxpbnV4cHM0MTAuaHpsYWIubGFiLmVtYy5jb22CHGxpbnV4cHM0
MTAuaHpsYWIubGFiLmVtYy5jb22CCmxpbnV4cHM0MTCCIHd3dy5saW51eHFhMTQw
Lmh6bGFiLmxhYi5lbWMuY29tghxsaW51eHFhMTQwLmh6bGFiLmxhYi5lbWMuY29t
ggpsaW51eHFhMTQwgiB3d3cubGludXhxYTEzMC5oemxhYi5sYWIuZW1jLmNvbYIc
bGludXhxYTEzMC5oemxhYi5sYWIuZW1jLmNvbYIKbGludXhxYTEzMIIgd3d3Lmxp
bnV4cWExMjAuaHpsYWIubGFiLmVtYy5jb22CHGxpbnV4cWExMjAuaHpsYWIubGFi
LmVtYy5jb22CCmxpbnV4cWExMjCCIHd3dy5saW51eHFhMTEwLmh6bGFiLmxhYi5l
bWMuY29tghxsaW51eHFhMTEwLmh6bGFiLmxhYi5lbWMuY29tggpsaW51eHFhMTEw
giZhbmFseXRpY3MubGludXhwczQxMC5oemxhYi5sYWIuZW1jLmNvbYImYW5hbHl0
aWNzLmxpbnV4cHM0MjAuaHpsYWIubGFiLmVtYy5jb22CJmFuYWx5dGljcy5saW51
eHFhMTEwLmh6bGFiLmxhYi5lbWMuY29tgiZhbmFseXRpY3MubGludXhxYTEyMC5o
emxhYi5sYWIuZW1jLmNvbYImYW5hbHl0aWNzLmxpbnV4cWExMzAuaHpsYWIubGFi
LmVtYy5jb22CJmFuYWx5dGljcy5saW51eHFhMTQwLmh6bGFiLmxhYi5lbWMuY29t
ggtsaW51eHBzcjIxMIIdbGludXhwc3IyMTAuaHpsYWIubGFiLmVtYy5jb22CIXd3
dy5saW51eHBzcjIxMC5oemxhYi5sYWIuZW1jLmNvbYIJbHhiYW1iYTAyghtseGJh
bWJhMDIuaHpsYWIubGFiLmVtYy5jb22CH3d3dy5seGJhbWJhMDIuaHpsYWIubGFi
LmVtYy5jb22CHHd3dy5sbnFhMTEuaHpsYWIubGFiLmVtYy5jb22CBmxucWExMYIY
bG5xYTExLmh6bGFiLmxhYi5lbWMuY29tghx3d3cubG5xYTIyLmh6bGFiLmxhYi5l
bWMuY29tggZsbnFhMjKCGGxucWEyMi5oemxhYi5sYWIuZW1jLmNvbYIKbGludXhx
YTIzMIIcbGludXhxYTIzMC5oemxhYi5sYWIuZW1jLmNvbYIgd3d3LmxpbnV4cWEy
MzAuaHpsYWIubGFiLmVtYy5jb22CCmxpbnV4cWExMTKCHGxpbnV4cWExMTIuaHps
YWIubGFiLmVtYy5jb22CIHd3dy5saW51eHFhMTEyLmh6bGFiLmxhYi5lbWMuY29t
ghMqLmh6bGFiLmxhYi5lbWMuY29tMB0GA1UdDgQWBBR4MEFEbM0o31wVN40iwOD/
m9QpijCBlgYDVR0jBIGOMIGLgBT56RbNdks3JmJmtnsp/eAEwn6DmaFvpG0wazEL
MAkGA1UEBhMCSUwxCzAJBgNVBAgMAk5BMREwDwYDVQQHDAhIZXJ6ZWxpYTEXMBUG
A1UECgwOUlNBIENvcnAsIEluYy4xDDAKBgNVBAsMAzNEUzEVMBMGA1UEAwwMM0RT
IFJvb3QgSFNNggISTTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAX
E64tiFNJFd9BQVH2x+PqM9l2oX835PVk8e98tjpmoPpc+t89Ei0uSFrIHO0gmI/W
X3aPPdUsusdn6KUlg9x6ID/3EVB8mkrP8ShFHMXamDXLrfLkV/R23DwBJKNkskm3
c6YnDRANmo8uwWynj66tFBPo3inSJaPQa27ZAPBU+vhF7YlGjQ3ZSDi2FoAyEyUe
zThBF0+G9Opu0F2URqHVBqcgPtzOC9WFqAGlI0g7spr6XEvnnQR5cN+rDadXIqs9
g30bF8NoMe6qaZNw1Vx1SUg4+YEm7knTf33ACHSI2Z9F4D+87MGvKiFqeUgrDjRM
HYQJOr1SLsO/Bl54bt8d
-----END CERTIFICATE-----";
    }
}
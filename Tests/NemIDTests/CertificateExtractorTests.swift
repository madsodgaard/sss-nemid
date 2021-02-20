import XCTest
@testable import NemID

final class CertificateExtractorTests: XCTestCase {
    func test_extract_extractsChain() throws {
        let sut = CertificatesExtractor()
        let response = ParsedXMLDSigResponse(signatureValue: "", signedInfo: "", referenceDigestValue: "", objectToBeSigned: "", x509Certificates: [globalSignCert, googleTrustCert, googleComCer])
        
        let chain = try sut.extract(from: response)
        try XCTAssertEqual(chain.root, X509Certificate(der: Data(base64Encoded: globalSignCert, options: .ignoreUnknownCharacters)!))
        try XCTAssertEqual(chain.intermediate, X509Certificate(der: Data(base64Encoded: googleTrustCert, options: .ignoreUnknownCharacters)!))
        try XCTAssertEqual(chain.leaf, X509Certificate(der: Data(base64Encoded: googleComCer, options: .ignoreUnknownCharacters)!))
    }
}

// Taken from google.com
let globalSignCert = """
MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4G
A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNp
Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1
MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEG
A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8omUVCxKs+IVSbC9N/hHD6ErPL
v4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7SqbKSaZeqKeMWhG8
eoLrvozps6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQBoZfXklq
tTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzd
C9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pa
zq+r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCB
mTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUm+IH
V2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5n
bG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG
3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4Gs
J0/WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO
291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavS
ot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG79G+dwfCMNYxd
AfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7
TBj0/VLZjmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg==
"""

// GTS CA 101
let googleTrustCert = """
MIIESjCCAzKgAwIBAgINAeO0mqGNiqmBJWlQuDANBgkqhkiG9w0BAQsFADBMMSAw
HgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFs
U2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNzA2MTUwMDAwNDJaFw0yMTEy
MTUwMDAwNDJaMEIxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVHb29nbGUgVHJ1c3Qg
U2VydmljZXMxEzARBgNVBAMTCkdUUyBDQSAxTzEwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQDQGM9F1IvN05zkQO9+tN1pIRvJzzyOTHW5DzEZhD2ePCnv
UA0Qk28FgICfKqC9EksC4T2fWBYk/jCfC3R3VZMdS/dN4ZKCEPZRrAzDsiKUDzRr
mBBJ5wudgzndIMYcLe/RGGFl5yODIKgjEv/SJH/UL+dEaltN11BmsK+eQmMF++Ac
xGNhr59qM/9il71I2dN8FGfcddwuaej4bXhp0LcQBbjxMcI7JP0aM3T4I+DsaxmK
FsbjzaTNC9uzpFlgOIg7rR25xoynUxv8vNmkq7zdPGHXkxWY7oG9j+JkRyBABk7X
rJfoucBZEqFJJSPk7XA0LKW0Y3z5oz2D0c1tJKwHAgMBAAGjggEzMIIBLzAOBgNV
HQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1Ud
EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFJjR+G4Q68+b7GCfGJAboOt9Cf0rMB8G
A1UdIwQYMBaAFJviB1dnHB7AagbeWbSaLd/cGYYuMDUGCCsGAQUFBwEBBCkwJzAl
BggrBgEFBQcwAYYZaHR0cDovL29jc3AucGtpLmdvb2cvZ3NyMjAyBgNVHR8EKzAp
MCegJaAjhiFodHRwOi8vY3JsLnBraS5nb29nL2dzcjIvZ3NyMi5jcmwwPwYDVR0g
BDgwNjA0BgZngQwBAgIwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly9wa2kuZ29vZy9y
ZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEAGoA+Nnn78y6pRjd9XlQWNa7H
TgiZ/r3RNGkmUmYHPQq6Scti9PEajvwRT2iWTHQr02fesqOqBY2ETUwgZQ+lltoN
FvhsO9tvBCOIazpswWC9aJ9xju4tWDQH8NVU6YZZ/XteDSGU9YzJqPjY8q3MDxrz
mqepBCf5o8mw/wJ4a2G6xzUr6Fb6T8McDO22PLRL6u3M4Tzs3A2M1j6bykJYi8wW
IRdAvKLWZu/axBVbzYmqmwkm5zLSDW5nIAJbELCQCZwMH56t2Dvqofxs6BBcCFIZ
USpxu6x6td0V7SvJCCosirSmIatj/9dSSVDQibet8q/7UK4v4ZUN80atnZz1yg==
"""

let googleComCer = """
MIIJhjCCCG6gAwIBAgIRAJqpJQj6G3+pBQAAAACHSiYwDQYJKoZIhvcNAQELBQAw
QjELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczET
MBEGA1UEAxMKR1RTIENBIDFPMTAeFw0yMTAxMjYwOTAxMDBaFw0yMTA0MjAwOTAw
NTlaMGYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
Ew1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMRUwEwYDVQQDDAwq
Lmdvb2dsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT8QvapiMbhr4Y+
4OFNjzBtA+z3RazinqH9g7wuPyCRyXUUngSqZ7tG1obEt4qJCHi1TbttnCyjlDDM
VxMdaLmxo4IHHDCCBxgwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUF
BwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFNTp8uOAUxKdFY2bcsGoeoQlgV08
MB8GA1UdIwQYMBaAFJjR+G4Q68+b7GCfGJAboOt9Cf0rMGgGCCsGAQUFBwEBBFww
WjArBggrBgEFBQcwAYYfaHR0cDovL29jc3AucGtpLmdvb2cvZ3RzMW8xY29yZTAr
BggrBgEFBQcwAoYfaHR0cDovL3BraS5nb29nL2dzcjIvR1RTMU8xLmNydDCCBNcG
A1UdEQSCBM4wggTKggwqLmdvb2dsZS5jb22CDSouYW5kcm9pZC5jb22CFiouYXBw
ZW5naW5lLmdvb2dsZS5jb22CCSouYmRuLmRldoISKi5jbG91ZC5nb29nbGUuY29t
ghgqLmNyb3dkc291cmNlLmdvb2dsZS5jb22CGCouZGF0YWNvbXB1dGUuZ29vZ2xl
LmNvbYITKi5mbGFzaC5hbmRyb2lkLmNvbYIGKi5nLmNvgg4qLmdjcC5ndnQyLmNv
bYIRKi5nY3BjZG4uZ3Z0MS5jb22CCiouZ2dwaHQuY26CDiouZ2tlY25hcHBzLmNu
ghYqLmdvb2dsZS1hbmFseXRpY3MuY29tggsqLmdvb2dsZS5jYYILKi5nb29nbGUu
Y2yCDiouZ29vZ2xlLmNvLmlugg4qLmdvb2dsZS5jby5qcIIOKi5nb29nbGUuY28u
dWuCDyouZ29vZ2xlLmNvbS5hcoIPKi5nb29nbGUuY29tLmF1gg8qLmdvb2dsZS5j
b20uYnKCDyouZ29vZ2xlLmNvbS5jb4IPKi5nb29nbGUuY29tLm14gg8qLmdvb2ds
ZS5jb20udHKCDyouZ29vZ2xlLmNvbS52boILKi5nb29nbGUuZGWCCyouZ29vZ2xl
LmVzggsqLmdvb2dsZS5mcoILKi5nb29nbGUuaHWCCyouZ29vZ2xlLml0ggsqLmdv
b2dsZS5ubIILKi5nb29nbGUucGyCCyouZ29vZ2xlLnB0ghIqLmdvb2dsZWFkYXBp
cy5jb22CDyouZ29vZ2xlYXBpcy5jboIRKi5nb29nbGVjbmFwcHMuY26CFCouZ29v
Z2xlY29tbWVyY2UuY29tghEqLmdvb2dsZXZpZGVvLmNvbYIMKi5nc3RhdGljLmNu
gg0qLmdzdGF0aWMuY29tghIqLmdzdGF0aWNjbmFwcHMuY26CCiouZ3Z0MS5jb22C
CiouZ3Z0Mi5jb22CFCoubWV0cmljLmdzdGF0aWMuY29tggwqLnVyY2hpbi5jb22C
ECoudXJsLmdvb2dsZS5jb22CEyoud2Vhci5na2VjbmFwcHMuY26CFioueW91dHVi
ZS1ub2Nvb2tpZS5jb22CDSoueW91dHViZS5jb22CFioueW91dHViZWVkdWNhdGlv
bi5jb22CESoueW91dHViZWtpZHMuY29tggcqLnl0LmJlggsqLnl0aW1nLmNvbYIa
YW5kcm9pZC5jbGllbnRzLmdvb2dsZS5jb22CC2FuZHJvaWQuY29tghtkZXZlbG9w
ZXIuYW5kcm9pZC5nb29nbGUuY26CHGRldmVsb3BlcnMuYW5kcm9pZC5nb29nbGUu
Y26CBGcuY2+CCGdncGh0LmNuggxna2VjbmFwcHMuY26CBmdvby5nbIIUZ29vZ2xl
LWFuYWx5dGljcy5jb22CCmdvb2dsZS5jb22CD2dvb2dsZWNuYXBwcy5jboISZ29v
Z2xlY29tbWVyY2UuY29tghhzb3VyY2UuYW5kcm9pZC5nb29nbGUuY26CCnVyY2hp
bi5jb22CCnd3dy5nb28uZ2yCCHlvdXR1LmJlggt5b3V0dWJlLmNvbYIUeW91dHVi
ZWVkdWNhdGlvbi5jb22CD3lvdXR1YmVraWRzLmNvbYIFeXQuYmUwIQYDVR0gBBow
GDAIBgZngQwBAgIwDAYKKwYBBAHWeQIFAzAzBgNVHR8ELDAqMCigJqAkhiJodHRw
Oi8vY3JsLnBraS5nb29nL0dUUzFPMWNvcmUuY3JsMIIBBAYKKwYBBAHWeQIEAgSB
9QSB8gDwAHYARJRlLrDuzq/EQAfYqP4owNrmgr7YyzG1P9MzlrW2gagAAAF3PiOs
rwAABAMARzBFAiBDskoT+4DqcMDSldu098kMmLvY+AypNh0KZ8VamQCvTwIhAJTT
z7ZfC3Wfpqcadew28ec02h1lhZLVvHzKB0lzBoG3AHYA9lyUL9F3MCIUVBgIMJRW
juNNExkzv98MLyALzE7xZOMAAAF3PiOsdAAABAMARzBFAiBsQrL6gy/xRMBycKa8
Gwnx/QHDGRSlBwSFwzkA5vT3igIhAKz3KKczktiE1FSrk9zFwBOqxksw/wIvr+PP
sWnJ/Do3MA0GCSqGSIb3DQEBCwUAA4IBAQCr82gezpbU0GfnG7o02H70mjouQBZQ
lNM8JuNXz/aU+CrwoYJ//esxVNpPrMixBTOmafHCLDnsVeNbCHpJ2AU/ZTgl4x/l
zB3CLZ4PsHo8vyFwIvbRX2biQRhWBdF53bvEjAddkHMSS+sja/EPDZqIt09/040D
1QvnVB8COV4oEXGUOo5NsmS5Xg9GPqSB55YMUT3qesThh6FWZgwHNOsYkGDX2/qr
QslRN0DGtMWV0ov9HcRUJ9zktAxMHsAQPZkl1VDLK9fOZiotwcASXZIwPeyHa4kh
9AIGDv5ZLD2L1fAhrmD+KyK3XqRYlN3C0wu5AASOwK2j/MS3nvTPZVCO
"""

import Foundation
@testable import NemID
import XCTest

final class OCSPResponseTests: XCTestCase {
    func test_init_withUnauthorizedResponse() throws {
        let response = try OCSPResponse(from: [UInt8](Data(base64Encoded: unauthorizedOcspResponse)!))
        XCTAssertEqual(response.responseStatus, .unauthorized)
        XCTAssertNil(response.basicOCSPResponse)
    }
    
    func test_init_withSuccesfulResponse() throws {
        let response = try OCSPResponse(from: [UInt8](Data(base64Encoded: successfulOcspResponse)!))
        let basicResponse = try XCTUnwrap(response.basicOCSPResponse)
        let singleResponse = try XCTUnwrap(basicResponse.tbsResponseData.responses.first)
        let certificate = try XCTUnwrap(basicResponse.certs.first)
        
        let expectedSignature = "xo6zSJb7gemfLet4Y8OHhUMSvKv1ipdQ5HGPHeItShBSo4plJH2+8JvqbZ5ofaFJWzryaBZo2FT7xTbOZcCJ4W/GZwi1Yx/+otWVSi1WyREoqzSmSCBxN+fXOzl0X1j+9QrsaG122gd0qDWBZi1muLiRwXiLdQTX1CI8txxv7N6HlZoIf6iY+TgxoKJtExf3pH9By2BGof57ygwIUrcc+TXGbQoohPlu3RB1IqKIKc1nbajb9deIap0ZAsHfuv9n3P5epIw80VKCbSXrTUjEhP7WGR1lA6IqVTiUohXL7TYDIUKwMY6DgZ44A+1OYdRoajt4HB2KuHVZUfaW76RFEg=="
        
        XCTAssertEqual(response.responseStatus, .successful)
        XCTAssertEqual(basicResponse.signatureAlgorithm, .sha1WithRSAEncryption)
        XCTAssertEqual(basicResponse.certs.count, 1)
        XCTAssertEqual(Data(basicResponse.signature).base64EncodedString(), expectedSignature)
        XCTAssertEqual(singleResponse.certStatus, .good)
        XCTAssertEqual(singleResponse.thisUpdate, Date(year: 2021, month: 04, day: 19, hour: 11, minute: 35, second: 08))
        XCTAssertEqual(singleResponse.nextUpdate, Date(year: 2021, month: 04, day: 20, hour: 02, minute: 50, second: 17))
        XCTAssertEqual(singleResponse.certID.hashAlgorithm, .sha256)
        XCTAssertEqual(singleResponse.certID.issuerNameHash.hexEncodedString(uppercase: true), "4DF13F909A02EB818EC1C353DE918DF9A4FB4C22E1300351A86682A59CD1AC51")
        XCTAssertEqual(singleResponse.certID.issuerKeyHash.hexEncodedString(uppercase: true), "4739EC449DF2CEC9AAE1D6271251C57406C24685AB4C11ABD67301A47E985144")
        XCTAssertEqual(singleResponse.certID.serialNumber.hexEncodedString(uppercase: true), "5F9C324B")
        XCTAssertEqual(certificate.subjectCommonName, "DANID A/S - Systemtest XXXIV OCSP Responder 02")
    }
    
    /*
     OCSP Response Data:
     OCSP Response Status: successful (0x0)
     Response Type: Basic OCSP Response
     Version: 1 (0x0)
     Responder Id: 83AC750FB200DB852BA56E4A90C8965C1F069F6D
     Produced At: Apr 19 14:50:17 2021 GMT
     Responses:
     Certificate ID:
     Hash Algorithm: sha256
     Issuer Name Hash: 4DF13F909A02EB818EC1C353DE918DF9A4FB4C22E1300351A86682A59CD1AC51
     Issuer Key Hash: 4739EC449DF2CEC9AAE1D6271251C57406C24685AB4C11ABD67301A47E985144
     Serial Number: 5F9C324B
     Cert Status: good
     This Update: Apr 19 11:35:08 2021 GMT
     Next Update: Apr 20 02:50:17 2021 GMT
     
     Signature Algorithm: sha1WithRSAEncryption
     c6:8e:b3:48:96:fb:81:e9:9f:2d:eb:78:63:c3:87:85:43:12:
     bc:ab:f5:8a:97:50:e4:71:8f:1d:e2:2d:4a:10:52:a3:8a:65:
     24:7d:be:f0:9b:ea:6d:9e:68:7d:a1:49:5b:3a:f2:68:16:68:
     d8:54:fb:c5:36:ce:65:c0:89:e1:6f:c6:67:08:b5:63:1f:fe:
     a2:d5:95:4a:2d:56:c9:11:28:ab:34:a6:48:20:71:37:e7:d7:
     3b:39:74:5f:58:fe:f5:0a:ec:68:6d:76:da:07:74:a8:35:81:
     66:2d:66:b8:b8:91:c1:78:8b:75:04:d7:d4:22:3c:b7:1c:6f:
     ec:de:87:95:9a:08:7f:a8:98:f9:38:31:a0:a2:6d:13:17:f7:
     a4:7f:41:cb:60:46:a1:fe:7b:ca:0c:08:52:b7:1c:f9:35:c6:
     6d:0a:28:84:f9:6e:dd:10:75:22:a2:88:29:cd:67:6d:a8:db:
     f5:d7:88:6a:9d:19:02:c1:df:ba:ff:67:dc:fe:5e:a4:8c:3c:
     d1:52:82:6d:25:eb:4d:48:c4:84:fe:d6:19:1d:65:03:a2:2a:
     55:38:94:a2:15:cb:ed:36:03:21:42:b0:31:8e:83:81:9e:38:
     03:ed:4e:61:d4:68:6a:3b:78:1c:1d:8a:b8:75:59:51:f6:96:
     ef:a4:45:12
     Certificate:
     Data:
     Version: 3 (0x2)
     Serial Number: 1604072134 (0x5f9c32c6)
     Signature Algorithm: sha256WithRSAEncryption
     Issuer: C=DK, O=TRUST2408, CN=TRUST2408 Systemtest XXXIV CA
     Validity
     Not Before: Apr 19 01:00:39 2021 GMT
     Not After : Apr 22 01:00:38 2021 GMT
     Subject: C=DK, O=DANID A/S // CVR:30808460/serialNumber=CVR:30808460-UID:OCSP01-SYSTEMTEST-XXXIV, CN=DANID A/S - Systemtest XXXIV OCSP Responder 02
     Subject Public Key Info:
     Public Key Algorithm: rsaEncryption
     Public-Key: (2048 bit)
     Modulus:
     00:c8:92:0d:eb:c0:af:6a:6d:67:46:48:cb:97:0f:
     02:2d:13:0d:b9:e7:7a:26:59:dc:79:dd:8d:7d:b5:
     3a:5f:fc:57:bb:e1:00:20:e8:94:35:94:bc:6f:4c:
     38:2a:d0:fa:cb:7b:7c:4e:96:c3:ea:0a:d1:66:8d:
     22:9f:0c:a0:3a:1d:1b:31:01:71:df:45:1c:de:25:
     39:07:e5:e4:78:9b:03:30:d3:87:73:c5:77:33:4d:
     b4:59:f4:20:fa:be:ab:e4:a1:c5:2b:d1:4f:be:c2:
     63:47:68:a2:56:55:5c:a1:17:c6:a5:35:08:20:b2:
     01:d2:bb:98:79:76:6f:71:3f:12:f4:a9:6f:d8:a3:
     9e:70:9f:5d:3e:64:3a:b9:71:3e:5f:64:7f:d7:c1:
     4c:a9:a1:84:0b:10:4e:d3:35:4b:fb:c0:81:c7:df:
     34:b3:70:4e:e7:a1:0d:bc:f0:2d:a4:95:ba:de:a0:
     4d:53:9d:3c:9b:a0:f4:92:34:60:de:e2:ee:67:be:
     b9:f6:96:af:64:0c:b2:df:18:17:f8:eb:26:e6:c3:
     76:c6:c5:64:35:97:d4:a4:fc:cc:3a:95:56:6e:d0:
     80:30:a7:97:0a:eb:49:94:ad:1f:83:0f:b3:08:80:
     2d:44:25:36:37:a8:75:10:12:47:af:1d:40:62:b4:
     9b:35
     Exponent: 65537 (0x10001)
     X509v3 extensions:
     X509v3 Key Usage: critical
     Digital Signature
     OCSP No Check:
     
     X509v3 Extended Key Usage:
     OCSP Signing
     X509v3 Certificate Policies:
     Policy: 1.3.6.1.4.1.31313.2.4.6.3.5
     CPS: http://www.trust2408.com/repository
     User Notice:
     Organization: DanID
     Number: 1
     Explicit Text: DanID test certifikater fra denne CA udstedes under OID 1.3.6.1.4.1.31313.2.4.6.3.5. DanID test certificates from this CA are issued under OID 1.3.6.1.4.1.31313.2.4.6.3.5.
     
     X509v3 Authority Key Identifier:
     keyid:CD:6C:68:97:39:72:19:A4:35:AB:64:EA:F4:11:A3:81:87:F8:69:3B
     
     X509v3 Subject Key Identifier:
     83:AC:75:0F:B2:00:DB:85:2B:A5:6E:4A:90:C8:96:5C:1F:06:9F:6D
     X509v3 Basic Constraints:
     CA:FALSE
     Signature Algorithm: sha256WithRSAEncryption
     96:1d:e6:5d:b1:7f:cf:3d:a7:1a:0f:f4:c9:f3:90:ab:ad:73:
     d8:05:84:5f:c7:6e:8b:86:cb:50:b2:02:d7:20:c8:91:88:71:
     63:01:9c:ed:5a:33:2c:0a:5f:17:e5:6d:cd:ab:34:fb:86:94:
     86:62:e5:bf:10:81:f7:1c:58:e5:a5:37:98:0f:8e:a0:47:0e:
     3d:18:0c:8d:94:93:cb:47:38:88:5c:40:3b:5b:88:c4:80:8a:
     be:19:fb:7c:c0:38:d2:e3:77:60:7d:a2:36:16:7d:c1:6d:58:
     e9:27:58:cb:64:97:a4:ee:a3:06:bb:d3:f4:1a:75:ea:9b:c1:
     b7:fd:d6:56:f3:2b:48:d5:4d:27:94:80:6a:95:bf:8d:02:23:
     7b:58:06:af:45:b6:18:9a:d0:ae:66:30:7b:01:6e:09:b5:d7:
     4e:e8:9c:f3:a7:be:ab:61:55:69:47:8a:f2:57:7a:04:2d:81:
     92:1f:e3:6c:0b:0e:0f:a3:87:e6:0f:50:f7:7b:bc:de:27:fe:
     4d:d4:3b:15:50:83:33:c1:4a:21:08:1a:44:94:5c:76:6e:ea:
     11:af:95:12:78:58:7f:0c:e2:a8:38:24:2b:18:fe:e5:01:be:
     da:d6:32:52:49:56:e0:6a:44:91:40:1e:c0:73:78:3c:3a:85:
     e2:31:86:71
     -----BEGIN CERTIFICATE-----
     MIIFDjCCA/agAwIBAgIEX5wyxjANBgkqhkiG9w0BAQsFADBJMQswCQYDVQQGEwJE
     SzESMBAGA1UECgwJVFJVU1QyNDA4MSYwJAYDVQQDDB1UUlVTVDI0MDggU3lzdGVt
     dGVzdCBYWFhJViBDQTAeFw0yMTA0MTkwMTAwMzlaFw0yMTA0MjIwMTAwMzhaMIGb
     MQswCQYDVQQGEwJESzEiMCAGA1UECgwZREFOSUQgQS9TIC8vIENWUjozMDgwODQ2
     MDFoMC8GA1UEBRMoQ1ZSOjMwODA4NDYwLVVJRDpPQ1NQMDEtU1lTVEVNVEVTVC1Y
     WFhJVjA1BgNVBAMMLkRBTklEIEEvUyAtIFN5c3RlbXRlc3QgWFhYSVYgT0NTUCBS
     ZXNwb25kZXIgMDIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDIkg3r
     wK9qbWdGSMuXDwItEw2553omWdx53Y19tTpf/Fe74QAg6JQ1lLxvTDgq0PrLe3xO
     lsPqCtFmjSKfDKA6HRsxAXHfRRzeJTkH5eR4mwMw04dzxXczTbRZ9CD6vqvkocUr
     0U++wmNHaKJWVVyhF8alNQggsgHSu5h5dm9xPxL0qW/Yo55wn10+ZDq5cT5fZH/X
     wUypoYQLEE7TNUv7wIHH3zSzcE7noQ288C2klbreoE1TnTyboPSSNGDe4u5nvrn2
     lq9kDLLfGBf46ybmw3bGxWQ1l9Sk/Mw6lVZu0IAwp5cK60mUrR+DD7MIgC1EJTY3
     qHUQEkevHUBitJs1AgMBAAGjggGpMIIBpTAOBgNVHQ8BAf8EBAMCB4AwDwYJKwYB
     BQUHMAEFBAIFADATBgNVHSUEDDAKBggrBgEFBQcDCTCCASAGA1UdIASCARcwggET
     MIIBDwYNKwYBBAGB9FECBAYDBTCB/TAvBggrBgEFBQcCARYjaHR0cDovL3d3dy50
     cnVzdDI0MDguY29tL3JlcG9zaXRvcnkwgckGCCsGAQUFBwICMIG8MAwWBURhbklE
     MAMCAQEagatEYW5JRCB0ZXN0IGNlcnRpZmlrYXRlciBmcmEgZGVubmUgQ0EgdWRz
     dGVkZXMgdW5kZXIgT0lEIDEuMy42LjEuNC4xLjMxMzEzLjIuNC42LjMuNS4gRGFu
     SUQgdGVzdCBjZXJ0aWZpY2F0ZXMgZnJvbSB0aGlzIENBIGFyZSBpc3N1ZWQgdW5k
     ZXIgT0lEIDEuMy42LjEuNC4xLjMxMzEzLjIuNC42LjMuNS4wHwYDVR0jBBgwFoAU
     zWxolzlyGaQ1q2Tq9BGjgYf4aTswHQYDVR0OBBYEFIOsdQ+yANuFK6VuSpDIllwf
     Bp9tMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQELBQADggEBAJYd5l2xf889pxoP9Mnz
     kKutc9gFhF/HbouGy1CyAtcgyJGIcWMBnO1aMywKXxflbc2rNPuGlIZi5b8Qgfcc
     WOWlN5gPjqBHDj0YDI2Uk8tHOIhcQDtbiMSAir4Z+3zAONLjd2B9ojYWfcFtWOkn
     WMtkl6Tuowa70/Qadeqbwbf91lbzK0jVTSeUgGqVv40CI3tYBq9Fthia0K5mMHsB
     bgm1107onPOnvqthVWlHivJXegQtgZIf42wLDg+jh+YPUPd7vN4n/k3UOxVQgzPB
     SiEIGkSUXHZu6hGvlRJ4WH8M4qg4JCsY/uUBvtrWwMlJJVuBqRJFAHsBzeDw6heIx
     hnE=
     -----END CERTIFICATE-----
     */
    private let successfulOcspResponse = "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"
    
    private let unauthorizedOcspResponse = "MAMKAQY="
}

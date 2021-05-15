import Foundation
import XCTest
import Clibxml2
@testable import NemID

final class libxml2XMLDigParserTests: XCTestCase {
    let sut = libxml2XMLDSigParser()
    
    func test_parse_signatureValue_returnsSignatureValue() throws {
        let result = try sut.parse([UInt8](exampleXMLResponse.utf8))
        XCTAssertEqual(result.signatureValue, "signature-value")
    }
    
    func test_parse_referenceDigestValue_returnsFirstReferenceDigestValue() throws {
        let result = try sut.parse([UInt8](exampleXMLResponse.utf8))
        XCTAssertEqual(result.referenceDigestValue, "digest-value")
    }
    
    func test_parse_objectToBeSigned_returnsEntireXMLObject() throws {
        let result = try sut.parse([UInt8](exampleXMLStructure.utf8))
        XCTAssertEqual(String(data: result.objectToBeSigned, encoding: .utf8), """
        <ds:Object Id="ToBeSigned">
        <element>object</element>
        </ds:Object>
        """
        )
    }
    
    func test_parse_signedInfo_returnsEntireXMLObject() throws {
        let result = try sut.parse([UInt8](exampleXMLStructure.utf8))
        XCTAssertEqual(String(data: result.signedInfo, encoding: .utf8), """
        <ds:SignedInfo>
        <ds:Reference>
        <ds:DigestValue>digest-value</ds:DigestValue>
        </ds:Reference>
        </ds:SignedInfo>
        """
        )
    }
    
    func test_parse_x509Certificates_returnsArrayOfCerts() throws {
        let result = try sut.parse([UInt8](exampleXMLResponse.utf8))
        XCTAssertEqual(result.x509Certificates, ["cert1", "cert2", "cert3"])
    }
}

fileprivate let exampleXMLStructure = """
<openoces:signature xmlns:openoces="http://www.openoces.org/2006/07/signature#">
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:Reference>
<ds:DigestValue>digest-value</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>signature-value</ds:SignatureValue>
<ds:KeyInfo id="bidKeyInfo">
<ds:X509Data>
<ds:X509Certificate>cert1</ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
<ds:Object Id="ToBeSigned">
<element>object</element>
</ds:Object>
</ds:Signature>
</openoces:signature>
"""

fileprivate let exampleXMLResponse = """
<openoces:signature xmlns:openoces="http://www.openoces.org/2006/07/signature#">
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
   <ds:SignedInfo>
      <canonicalizationmethod algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <signaturemethod algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference type="http://www.bankid.com/signature/v1.0.0/types" uri="#bidSignedData">
         <transforms>
            <transform algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315">
         </transform></transforms>
        <digestmethod algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>digest-value</ds:DigestValue>
        </ds:Reference>
   </ds:SignedInfo>
   <ds:SignatureValue>signature-value</ds:SignatureValue>
   <ds:KeyInfo id="bidKeyInfo">
      <ds:X509Data>
         <ds:X509Certificate>cert1</ds:X509Certificate>
      </ds:X509Data>
      <ds:X509Data>
         <ds:X509Certificate>cert2</ds:X509Certificate>
      </ds:X509Data>
      <ds:X509Data>
         <ds:X509Certificate>cert3</ds:X509Certificate>
      </ds:X509Data>
   </ds:KeyInfo>
   <ds:Object Id="ToBeSigned">
      <bankidsigneddata xmlns="http://www.bankid.com/signature/v1.0.0/types">
         <srvinfo>
            <name>Y249WmlnblNlYyBBQixuYW1lPVppZ25TZWMsc2VyaWFsTnVtYmVyPTU1OTAxNjUyNjEsbz1Td2VkYmFuayBBQiAocHVibCksYz1TRQ==</name>
            <nonce>ce2Y4SkxhA5xViXqfNoSxh75j1w=</nonce>
            <displayname>WmlnblNlYw==</displayname>
         </srvinfo>
         <clientinfo>
            <funcid>Identification</funcid>
            <version>Ny43LjA=</version>
            <env>
               <ai>
                  <type>V0lOX01PQg==</type>
                  <deviceinfo>MTAuMC4xNTI1NC4xMjQ=</deviceinfo>
                  <uhi>GexSnfhl52v1Y+yGwXYMgdxNhqs=</uhi>
                  <fsib>0</fsib>
                  <utb>cs1</utb>
                  <requirement>
                     <condition>
                        <type>CertificatePolicies</type>
                        <value>1.2.752.78.1.5</value>
                     </condition>
                  </requirement>
                  <uauth>pw</uauth>
               </ai>
            </env>
         </clientinfo>
      </bankidsigneddata>
   </ds:Object>
</ds:Signature>
</openoces:signature>
"""

#warning("actual response from nemid")
//<?xml version="1.0" encoding="UTF-8" ?>
//    <openoces:signature xmlns:openoces="http://www.openoces.org/2006/07/signature#" version="0.1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="signature">
//<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:openoces="http://www.openoces.org/2006/07/signature#">
//<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"></ds:CanonicalizationMethod>
//<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"></ds:SignatureMethod>
//<ds:Reference URI="#ToBeSigned">
//<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>
//<ds:DigestValue>uduKRPLbUp4KcoWA39ciGVALf4+sjXsrYH6Zl477pnk=</ds:DigestValue>
//</ds:Reference>
//</ds:SignedInfo>
//<ds:SignatureValue>
//UjZ2dH4GqV0shGyJXYRBptC+akAlL20DWnMIZ2NaQUOQBgIjopIbdgGb/ZOJkupPh0qz9aolu+kZ
//hHTYigYCn/7P3isyQ8Xl5/5ALnfpeY4iv8aNlAgLsHCVBap0NMJykEubUUpnlu3x1qBywOHVVqV8
//MnLHIKe/eIoEm8+EZVyvjDCyzHpp4G7O6rL7aoEgEjS6G3iXAf79X6m04m6/zuykjmCnb1kuFzwL
//Glw5XpVcRmlhOnn+y1LJLeBVwmYxCWr7cgk6MG5JHMMZ2Ob33JcJWg0yd4j19WzHUX7d0WsTV3pj
//RTJCY75I2Pu7Gix4CgOJnaJ9whERKjnoHE3n5Q==
//</ds:SignatureValue>
//<ds:KeyInfo>
//<ds:X509Data>
//<ds:X509Certificate>
//MIIFQjCCAyqgAwIBAgIEW6o/tzANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJESzESMBAGA1UE
//ChMJVFJVU1QyNDA4MSwwKgYDVQQDEyNUUlVTVDI0MDggU3lzdGVtdGVzdCBWSUkgUHJpbWFyeSBD
//QTAeFw0xOTA2MDYxMjQzMTdaFw0zNDA2MDYxMzEzMTdaMEkxCzAJBgNVBAYTAkRLMRIwEAYDVQQK
//DAlUUlVTVDI0MDgxJjAkBgNVBAMMHVRSVVNUMjQwOCBTeXN0ZW10ZXN0IFhYWElWIENBMIIBIjAN
//BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzMjlEpubMaSpLYQiTnL8WGWQDljBvFyL+mMYIdXd
//CwGbLeyLyt7KAyXC8mtExR+ax96Z9IDIjIIpw/4upjTtWHUV6Ia7sJImw7M81KeQ/ZVSCT+pXybc
//luR5HtVqBRa/kyvs49KbbBx5KQEh2t7UzXwY/yQyEvtzJ7pJdXbP/Zoievo6gJnZh/VMhquwbGQS
//UDLC6CtwYuyHtMPHF1Xgyglva76D8CD2ajzYNXZ7AqjwMc5S1bONLyDwFITvOCAMnJCG7CQat57E
//rN7qWBuDIkQGsFIFuqUtLTOk6IYrezKhoV9FwjAOwrTTSeJoa/IZlIrpyRoBAuTKFRDG34BinwID
//AQABo4IBKjCCASYwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwEQYDVR0gBAowCDAG
//BgRVHSAAMIGvBgNVHR8EgacwgaQwOqA4oDaGNGh0dHA6Ly9jcmwuc3lzdGVtdGVzdDcudHJ1c3Qy
//NDA4LmNvbS9zeXN0ZW10ZXN0Ny5jcmwwZqBkoGKkYDBeMQswCQYDVQQGEwJESzESMBAGA1UEChMJ
//VFJVU1QyNDA4MSwwKgYDVQQDEyNUUlVTVDI0MDggU3lzdGVtdGVzdCBWSUkgUHJpbWFyeSBDQTEN
//MAsGA1UEAxMEQ1JMMTAfBgNVHSMEGDAWgBQjukwxkOHTzNMbsxtatshFzdODlzAdBgNVHQ4EFgQU
//zWxolzlyGaQ1q2Tq9BGjgYf4aTswDQYJKoZIhvcNAQELBQADggIBAA9f3uvdFgbl6nmWstkoUQHD
///0JJyMQKtFhixeNH2NplFsuAd8WzKdsa+BdmO6NxbeTSptgIkjZe+hzPfJ/oikCYmvynJlJlqqnK
//qosxK7zVHd8szcKaWY1GxD9qNrcGj7u6MF3ruqaSDYPkeYHlQX/lmJatiFQ3O8MvG1iEczUheXJl
//tgCys6jOP3SVrj56DJCv0lgpiHKqChJW2nASBOxINjAS3dDn6rSJqCccDavdE+P7Zj4vMiL0IIig
//EdCscQSDcEy8Wxm03PMGJQwOKJ4Lkbsq8WbNcgm6KjXRy0EEW8Rbu/Sbf6MLl43xycfNol9vmo+M
//ctyQGgwIzK8PXSuO3Ni6YXOtXMuKXZ4f9cUxIyYWyabsnnWSWpNzjkP2RPbS0Hj2OE/S4ajthfMa
//G42ZZwUpAJbz0+gLmIZl8zpi7Mk+S51fJbWS6siagfSdfHScjKSkwMeR8SWk1c+D20B14t1m7VsA
//zGUpSh8Xrg7EPPCImKV5aE9CobPa0GvmbF1GC4G0TAkx6B7oegG6BvaP2VDKl7ZTWpPAe7lgovUw
//AlmlcxVnyUVWF71/8WZS5S72wJDpIup/EuyDHlisxc7G0TIySznnVDBy3UAZK+crK+5CzLiVhwPP
//WfIVTLN4fzSOpXT61YaVcqMl4rNG6J+ww9PcmaladZlEYmnuCcDs
//</ds:X509Certificate>
//</ds:X509Data>
//<ds:X509Data>
//<ds:X509Certificate>
//MIIGCjCCBPKgAwIBAgIEX5wySzANBgkqhkiG9w0BAQsFADBJMQswCQYDVQQGEwJESzESMBAGA1UE
//CgwJVFJVU1QyNDA4MSYwJAYDVQQDDB1UUlVTVDI0MDggU3lzdGVtdGVzdCBYWFhJViBDQTAeFw0y
//MTA0MTYxNjM4MDJaFw0yNDA0MTYxNjM2MDJaMHYxCzAJBgNVBAYTAkRLMSkwJwYDVQQKDCBJbmdl
//biBvcmdhbmlzYXRvcmlzayB0aWxrbnl0bmluZzE8MBUGA1UEAwwOVGhlcmVzaWEgS2rDpnIwIwYD
//VQQFExxQSUQ6OTIwOC0yMDAyLTItODcxMjk2MTUzNjEzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
//MIIBCgKCAQEAmTvdGCGcgSL+JJn8s6O8u/08RRL4AeMBRPxGAdnSEL4YHA7Vm6birOC6szKblkk6
//Nk02cdsBg6OJ27PcFGNLbliUGTXRP9XsUzxxrZU1sFoRs9KwMnYt75tfRGoEqNogxlwp22idDwVE
//S4wzaHN0u4WpZYJ8QbpcYRRTNKPa8cx1mFdlOdb4/6DDbHmUpB2i6QczrWRvZNN+oq9ow++7NQ14
//gNAn3OmOm9v3XVWbgJ+DCcfBp2nrSIvIDpzrRI8lIUs258bMRlOuHkkjka048Q5ATer1GJTII94V
//EPEHmbALu2+diectoBOKVeDmI0tF9ieEKy0mi6AU7PuUYEuzkQIDAQABo4ICyzCCAscwDgYDVR0P
//AQH/BAQDAgP4MIGVBggrBgEFBQcBAQSBiDCBhTA8BggrBgEFBQcwAYYwaHR0cDovL29jc3Auc3lz
//dGVtdGVzdDM0LnRydXN0MjQwOC5jb20vcmVzcG9uZGVyMEUGCCsGAQUFBzAChjlodHRwOi8vYWlh
//LnN5c3RlbXRlc3QzNC50cnVzdDI0MDguY29tL3N5c3RlbXRlc3QzNC1jYS5jZXIwggEgBgNVHSAE
//ggEXMIIBEzCCAQ8GDSsGAQQBgfRRAgQGAQUwgf0wLwYIKwYBBQUHAgEWI2h0dHA6Ly93d3cudHJ1
//c3QyNDA4LmNvbS9yZXBvc2l0b3J5MIHJBggrBgEFBQcCAjCBvDAMFgVEYW5JRDADAgEBGoGrRGFu
//SUQgdGVzdCBjZXJ0aWZpa2F0ZXIgZnJhIGRlbm5lIENBIHVkc3RlZGVzIHVuZGVyIE9JRCAxLjMu
//Ni4xLjQuMS4zMTMxMy4yLjQuNi4xLjUuIERhbklEIHRlc3QgY2VydGlmaWNhdGVzIGZyb20gdGhp
//cyBDQSBhcmUgaXNzdWVkIHVuZGVyIE9JRCAxLjMuNi4xLjQuMS4zMTMxMy4yLjQuNi4xLjUuMIGt
//BgNVHR8EgaUwgaIwPKA6oDiGNmh0dHA6Ly9jcmwuc3lzdGVtdGVzdDM0LnRydXN0MjQwOC5jb20v
//c3lzdGVtdGVzdDM0LmNybDBioGCgXqRcMFoxCzAJBgNVBAYTAkRLMRIwEAYDVQQKDAlUUlVTVDI0
//MDgxJjAkBgNVBAMMHVRSVVNUMjQwOCBTeXN0ZW10ZXN0IFhYWElWIENBMQ8wDQYDVQQDDAZDUkwx
//NDgwHwYDVR0jBBgwFoAUzWxolzlyGaQ1q2Tq9BGjgYf4aTswHQYDVR0OBBYEFH+z0jzI8XzRg0FR
//acyCkH7/71ZpMAkGA1UdEwQCMAAwDQYJKoZIhvcNAQELBQADggEBAHU5GXPYPhYcJOtHG92KpzZ+
//LsYx5mL7+k1+0nL218GKSM5EoGb0QNexpigP2ze+bf3DGsklcKP9Wu3EF8s5RzRYUgg7V97KT5cs
///aqHtltwZn6OqEkyChaCbmRPxatF2VXFQRH2UI/xZQ9o1snbjkwF/zKSaVkH4jo2PuTqobErJtnm
//tFZsHmR/6azmq60zvfGpxzBWfDP8AalcFff0rUv5QW9ZqEsWkdLRsWb+W0yYrlettEV+kymlg/t8
//JVXzj8/GrSexK5Q5sxE7icw1hu/fpcruWtMFCYXDj3b9RojmwoqmkRKnA0wka0jCV6PN3mZe+1po
//lSwZrrZpQXeTF1I=
//</ds:X509Certificate>
//</ds:X509Data>
//<ds:X509Data>
//<ds:X509Certificate>
//MIIGSDCCBDCgAwIBAgIES+pulDANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJESzESMBAGA1UE
//ChMJVFJVU1QyNDA4MSwwKgYDVQQDEyNUUlVTVDI0MDggU3lzdGVtdGVzdCBWSUkgUHJpbWFyeSBD
//QTAeFw0xMDA1MTIwODMyMTRaFw0zNzAxMTIwOTAyMTRaME8xCzAJBgNVBAYTAkRLMRIwEAYDVQQK
//EwlUUlVTVDI0MDgxLDAqBgNVBAMTI1RSVVNUMjQwOCBTeXN0ZW10ZXN0IFZJSSBQcmltYXJ5IENB
//MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApuuMpdHu/lXhQ+9TyecthOxrg5hPgxlK
//1rpjsyBNDEmOEpmOlK8ghyZ7MnSF3ffsiY+0jA51p+AQfYYuarGgUQVO+VM6E3VUdDpgWEksetCY
//Y8L7UrpyDeYx9oywT7E+YXH0vCoug5F9vBPnky7PlfVNaXPfgjh1+66mlUD9sV3fiTjDL12GkwOL
//t35S5BkcqAEYc37HT69N88QugxtaRl8eFBRumj1Mw0LBxCwl21GdVY4EjqH1Us7YtRMRJ2nEFTCR
//WHzm2ryf7BGd80YmtJeL6RoiidwlIgzvhoFhv4XdLHwzaQbdb9s141q2s9KDPZCGcgIgeXZdqY1V
//z7UBCMiBDG7q2S2ni7wpUMBye+iYVkvJD32srGCzpWqG7203cLyZCjq2oWuLkL807/Sk4sYleMA4
//YFqsazIfV+M0OVrJCCCkPysS10n/+ioleM0hnoxQiupujIGPcJMA8anqWueGIaKNZFA/m1IKwnn0
//CTkEm2aGTTEwpzb0+dCATlLyv6Ss3w+D7pqWCXsAVAZmD4pncX+/ASRZQd3oSvNQxUQr8EoxEULx
//Sae0CPRyGwQwswGpqmGm8kNPHjIC5ks2mzHZAMyTz3zoU3h/QW2T2U2+pZjUeMjYhyrReWRbOIBC
//izoOaoaNcSnPGUEohGUyLPTbZLpWsm3vjbyk7yvPqoUCAwEAAaOCASowggEmMA8GA1UdEwEB/wQF
//MAMBAf8wDgYDVR0PAQH/BAQDAgEGMBEGA1UdIAQKMAgwBgYEVR0gADCBrwYDVR0fBIGnMIGkMDqg
//OKA2hjRodHRwOi8vY3JsLnN5c3RlbXRlc3Q3LnRydXN0MjQwOC5jb20vc3lzdGVtdGVzdDcuY3Js
//MGagZKBipGAwXjELMAkGA1UEBhMCREsxEjAQBgNVBAoTCVRSVVNUMjQwODEsMCoGA1UEAxMjVFJV
//U1QyNDA4IFN5c3RlbXRlc3QgVklJIFByaW1hcnkgQ0ExDTALBgNVBAMTBENSTDEwHwYDVR0jBBgw
//FoAUI7pMMZDh08zTG7MbWrbIRc3Tg5cwHQYDVR0OBBYEFCO6TDGQ4dPM0xuzG1q2yEXN04OXMA0G
//CSqGSIb3DQEBCwUAA4ICAQCRJ9TM7sISJBHQwN8xdey4rxA0qT7NZdKICcIxyIC82HIOGAouKb3o
//HjIoMgxIUhA3xbU3Putr4+Smnc1Ldrw8AofLGlFYG2ypg3cpF9pdHrVdh8QiERozLwfNPDgVeCAn
//jKPNt8mu0FWBS32tiVM5DEOUwDpoDDRF27Ku9qTFH4IYg90wLHfLi+nqc2HwVBUgDt3tXU6zK4pz
//M0CpbrbOXPJOYHMvaw/4Em2r0PZD+QOagcecxPMWI65t2h/USbyO/ah3VKnBWDkPsMKjj5jEbBVR
//nGZdv5rcJb0cHqQ802eztziA4HTbSzBE4oRaVCrhXg/g6Jj8/tZlgxRI0JGgAX2dvWQyP4xhbxLN
//CVXPdvRV0g0ehKvhom1FGjIz975/DMavkybh0gzygq4sY9Fykl4oT4rDkDvZLYIxS4u1BrUJJJaD
//zHCeXmZqOhx8She+Fj9YwVVRGfxT4FL0Qd3WAtaCVyhSQ6SkZgrPvzAmxOUruI6XhEhYGlP5O8WF
//ETiATxuZAJNuKMJtibfRhMNsQ+TVv/ZPr5Swe+3DIQtmt1MIlGlTn4k40z4s6gDGKiFwAYXjd/kI
//D32R/hJPE41o9+3nd8aHZhBy2lF0jKAmr5a6Lbhg2O7zjGq7mQ3MceNeebuWXD44AxIinryzhqnE
//WI+BxdlFaia3U7o2+HYdHw==
//</ds:X509Certificate>
//</ds:X509Data>
//</ds:KeyInfo>
//<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:openoces="http://www.openoces.org/2006/07/signature#" Id="ToBeSigned"><ds:SignatureProperties>
//<ds:SignatureProperty Target="signature"><openoces:Name>RequestIssuer</openoces:Name><openoces:Value Encoding="base64" VisibleToSigner="yes">TG9vZmVycw==</openoces:Value></ds:SignatureProperty>
//<ds:SignatureProperty Target="signature"><openoces:Name>TimeStamp</openoces:Name><openoces:Value Encoding="xml" VisibleToSigner="no">1618591111004</openoces:Value></ds:SignatureProperty>
//<ds:SignatureProperty Target="signature"><openoces:Name>action</openoces:Name><openoces:Value Encoding="xml" VisibleToSigner="no">logon</openoces:Value></ds:SignatureProperty>
//<ds:SignatureProperty Target="signature"><openoces:Name>identityAssuranceLevel</openoces:Name><openoces:Value Encoding="xml" VisibleToSigner="no">1</openoces:Value></ds:SignatureProperty>
//</ds:SignatureProperties></ds:Object>
//</ds:Signature></openoces:signature>

import Foundation
import XCTest
@testable import NemID

final class SwiftyXMLDSigParserTests: XCTestCase {
    let sut = SwiftyXMLDSigParser()
    
    func test_parse_signatureValue_returnsSignatureValue() throws {
        let response = try sut.parse(xml)
        XCTAssertEqual(response.signatureValue, "signature-value")
    }
    
    func test_parse_referenceDigestValue_returnsFirstReferenceDigestValue() throws {
        let response = try sut.parse(xml)
        XCTAssertEqual(response.referenceDigestValue, "digest-value")
    }
    
    func test_parse_objectToBeSigned_returnsEntireXMLObject() throws {
        XCTFail()
    }
    
    func test_parse_signedInfo_returnsEntireXMLObject() throws {
        XCTFail()
    }
    
    func test_parse_x509Certificates_returnsArrayOfCerts() throws {
        let response = try sut.parse(xml)
        XCTAssertEqual(response.x509Certificates, ["cert1", "cert2", "cert3"])
    }
}

let xml = """
<ds:Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
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
         <ds:X509Certificate>cert2</ds:X509Certificate>
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
"""

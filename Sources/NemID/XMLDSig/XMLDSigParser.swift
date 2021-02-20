import Foundation
import SwiftyXMLParser

protocol XMLDSigParser {
    func parse(_ xml: String) throws -> ParsedXMLDSigResponse
}

enum SwiftyXMLDSigParserError: Error {
    case missingSignatureValue
    case missingReferenceDigestValue
    case missingObjectToBeSigned
}

struct SwiftyXMLDSigParser: XMLDSigParser {
    func parse(_ xml: String) throws -> ParsedXMLDSigResponse {
        let parser = try XML.parse(xml)
        
        guard let signatureValue = parser["ds:Signature", "ds:SignatureValue"].text else { throw SwiftyXMLDSigParserError.missingSignatureValue }
        let signedInfo = try parser["ds:Signature", "ds:SignedInfo"].asXML()
        guard let referenceDigestValue = parser["ds:Signature", "ds:SignedInfo", "ds:Reference"].first["ds:DigestValue"].text else { throw SwiftyXMLDSigParserError.missingReferenceDigestValue }
        guard let objectToBeSignedItem = parser["ds:Signature", "ds:Object"]
                .first(where: { $0.attributes["Id"] == "ToBeSigned" })?
                .first
        else { throw SwiftyXMLDSigParserError.missingObjectToBeSigned }
        let x509Certificates = parser["ds:Signature", "ds:KeyInfo", "ds:X509Data", "ds:X509Certificate"].compactMap(\.text)
        
        return try ParsedXMLDSigResponse(
            signatureValue: signatureValue,
            signedInfo: signedInfo,
            referenceDigestValue: referenceDigestValue,
            objectToBeSigned: objectToBeSignedItem.asXML(),
            x509Certificates: x509Certificates
        )
    }
}

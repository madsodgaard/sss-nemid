import Foundation
import SwiftyXMLParser

struct ParsedXMLDSigResponse {
    /// Returns the <SignatureValue> as text
    let signatureValue: String
    /// Returns the <SignatureValue> as text
    let signedInfo: String
    /// Returns the reference digest value as text.
    let referenceDigestValue: String
    /// Returns the <Object> body where the id is ToBeSigned.
    let objectToBeSigned: String
    /// Returns an array of X509 certificates
    let x509Certificates: [String]
}

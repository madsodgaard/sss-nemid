import Foundation

struct ParsedXMLDSigResponse {
    /// Returns the <SignatureValue> value as base64 encoded string
    let signatureValue: String
    /// Returns the <SignedInfo> element as XML data
    let signedInfo: Data
    /// Returns the reference digest value as base64 encoded string.
    let referenceDigestValue: String
    /// Returns the <Object> body where the id is ToBeSigned as XML data.
    let objectToBeSigned: Data
    /// Returns an array of X509 certificates
    let x509Certificates: [String]
}

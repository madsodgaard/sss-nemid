import Foundation

/// Represents the XML-DSig message sent by the NemID client to the backend for verification.
struct NemIDXMLDSigResponse: Decodable {
    let signature: Signature
}

// MARK: Signature
extension NemIDXMLDSigResponse {
    struct Signature: Decodable {
        let signedInfo: SignedInfo
        let keyInfo: KeyInfo
    }
}

// MARK: SignedInfo
extension NemIDXMLDSigResponse.Signature {
    struct SignedInfo: Decodable {
        
    }
}

// MARK: KeyInfo
extension NemIDXMLDSigResponse.Signature {
    struct KeyInfo: Decodable {
        let x509Data: X509Data
    }
}

// MARK: X509Data
extension NemIDXMLDSigResponse.Signature.KeyInfo {
    struct X509Data: Decodable {
        let x509Certificate: [String]
    }
}


import Foundation

enum SwiftyXMLDSigParserError: Error {
    case missingSignatureValue
    case missingReferenceDigestValue
    case missingObjectToBeSigned
}

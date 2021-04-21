import Foundation

enum NemIDX509CertificateError: Error {
    case failedToRetrievePublicKey
    case failedToGetSerialNumber
    case failedToRetrieveDERRepresentation
}

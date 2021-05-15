import Foundation

enum CertificateChainError: Error {
    case failedToDecodeCertificate
    case unexpectedCertificateCount(Int)
    case failedToLocateLeafCertificate
    case failedToLocateIntermediateCertificate
    case failedToLocateRootCertificate
    case leafIssuerWasNotIntermediate
    case intermediateIssuerWasNotRoot
    case rootWasNotSelfSigned
}

import Foundation

enum CertificateChainValidationError: Error {
    case certificateWasNotSignedByCorrectCertificate
    case failedToExtractCertificateDates
    case certificateIsOutsideValidTime
    case issuerDidNotHaveCAFlag
    case leafDidNotHaveDigitalSignatureKeyUsage
    case issuerDidNotHaveKeyCertSignKeyUsage
}

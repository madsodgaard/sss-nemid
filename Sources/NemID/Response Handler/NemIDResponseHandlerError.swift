import Foundation

enum NemIDResponseHandlerError: Error {
    case failedToExtractSignedInfo
    case failedToExtractReferenceDigest
    case failedToExtractObjectToBeSigned
    case failedToExtractSignatureValue
    case digestDidNotMatchSignedObject
    case signedInfoWasNotSignedByCertificate
    case certificateWasNotSignedByCorrectCertificate
    case failedToExtractCertificateDates
    case certificateIsOutsideValidTime
    case issuerDidNotHaveCAFlag
    case leafDidNotHaveDigitalSignatureKeyUsage
    case issuerDidNotHaveKeyCertSignKeyUsage
    case failedToGetUserName
    case failedToGetUserPID
}

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
    case ocspRequestWasNotSuccessful
    case ocspBasicResponseIsNotPresent
    case ocspCertificateNotFoundInResponse
    case ocspSignatureWasNotSignedByCertificate
    case ocspCertificateWasNotSignedByIssuer
    case ocspCertificateResponseNotPresent
    case ocspCertificateStatusIsNotGood
    case ocspCertificateWrongHashAlgorithm
    case ocspResponseIsOutsideAllowedTime
}

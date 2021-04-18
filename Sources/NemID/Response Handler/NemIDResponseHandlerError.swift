import Foundation

enum NemIDResponseHandlerError: Error {
    case failedToDecodeResponseAsBase64
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
    case ocspRequestWasNotSuccessful
    case ocspBasicResponseIsNotPresent
    case ocspCertificateNotFoundInResponse
    case ocspSignatureWasNotSignedByCertificate
    case ocspCertificateWasNotSignedByIssuer
    case ocspCertificateResponseNotPresent
    case ocspCertificateStatusIsNotGood
    case ocspCertificateWrongHashAlgorithm
    case ocspResponseIsOutsideAllowedTime
    case ocspCertificateDidNotHaveOCSPSigningExtendedKeyUsage
    case ocspCertificateHasNoCheckExtension
}

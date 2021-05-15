import Foundation

enum OCSPValidationError: Error {
    case requestWasNotSuccessful
    case basicResponseIsNotPresent
    case certificateNotFoundInResponse
    case signatureWasNotSignedByCertificate
    case certificateWasNotSignedByIssuer
    case certificateResponseNotPresent
    case certificateStatusIsNotGood
    case certificateWrongHashAlgorithm
    case responseIsOutsideAllowedTime
    case certificateDidNotHaveOCSPSigningExtendedKeyUsage
    case certificateNoCheckExtensionNotFound
    case serialNumberDidNotMatchRequest
    case issuerKeyHashDidNotMatchRequest
    case issuerNameHashDidNotMatchRequest
}

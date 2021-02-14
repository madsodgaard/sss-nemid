import Foundation
import Crypto

enum NemIDParameterSigningError: Error {
    case invalidData
}

struct NemIDParameterSigner {
    let rsaSigner: RSASigner
    
    func sign(_ parameters: NemIDUnsignedClientParameters) throws -> NemIDSignedClientParameters {
        guard let normalizedData = parameters.normalized.data(using: .utf8) else { throw NemIDParameterSigningError.invalidData }
        let digest = SHA256.hash(data: normalizedData)
        let base64ParamsDigest = Data(digest).base64EncodedString()
        let signedDigest = try rsaSigner.sign(normalizedData)
        let base64SignedDigest = Data(signedDigest).base64EncodedString()
        
        return NemIDSignedClientParameters(
            clientFlow: parameters.clientFlow,
            language: parameters.language,
            origin: parameters.origin,
            rememberUserID: parameters.rememberUserID,
            rememberUserIDInitialStatus: parameters.rememberUserIDInitialStatus,
            SPCert: parameters.SPCert,
            timestamp: parameters.timestamp,
            digestSignature: base64SignedDigest,
            paramsDigest: base64ParamsDigest)
    }
}


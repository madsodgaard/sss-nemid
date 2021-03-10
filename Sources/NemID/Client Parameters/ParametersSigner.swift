import Foundation
import Crypto

enum NemIDParameterSigningError: Error {
    case invalidData
}

public struct NemIDParametersSigner {
    private let rsaSigner: RSASigner
    
    public init(rsaSigner: RSASigner) {
        self.rsaSigner = rsaSigner
    }
    
    public func sign(_ parameters: NemIDUnsignedClientParameters) throws -> NemIDSignedClientParameters {
        let normalizedData = [UInt8](parameters.normalized.utf8)
        let digest = SHA256.hash(data: normalizedData)
        // RSASigner also SHA256 hashes the data.
        let signature = try rsaSigner.sign(normalizedData)
        
        let base64ParamsDigest = Data(digest).base64EncodedString()
        let base64SignedDigest = Data(signature).base64EncodedString()
        
        return NemIDSignedClientParameters(
            clientFlow: parameters.clientFlow,
            language: parameters.language,
            origin: parameters.origin,
            rememberUserID: parameters.rememberUserID,
            rememberUserIDInitialStatus: parameters.rememberUserIDInitialStatus,
            SPCert: parameters.SPCert,
            timestamp: parameters.timestamp,
            digestSignature: base64SignedDigest,
            paramsDigest: base64ParamsDigest
        )
    }
}


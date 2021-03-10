import Foundation
import Crypto

enum NemIDParameterSigningError: Error {
    case invalidData
}

struct NemIDParametersSigner {
    private let rsaSigner: RSASigner
    private let configuration: NemIDConfiguration
    
    public init(rsaSigner: RSASigner, configuration: NemIDConfiguration) {
        self.rsaSigner = rsaSigner
        self.configuration = configuration
    }
    
    public func sign(_ parameters: NemIDUnsignedClientParameters) throws -> NemIDSignedClientParameters {
        let normalizedData = [UInt8](normalizedParameters(parameters).utf8)
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
            SPCert: configuration.spCertificate,
            timestamp: parameters.timestamp,
            digestSignature: base64SignedDigest,
            paramsDigest: base64ParamsDigest
        )
    }
    
    /// Returns a normalized string of the parameters, as described in the NemID documentation.
    ///
    /// 1. The parameters are sorted alphabetically by name. The sorting is case-insensitive.
    /// 2. Each parameter is concatenated to the result string as an alternating sequence of name and value
    private func normalizedParameters(_ unsignedParameters: NemIDUnsignedClientParameters) -> String {
        var parameters: [String: String] = [
            "CLIENTFLOW": unsignedParameters.clientFlow.rawValue,
            "LANGUAGE": unsignedParameters.language.rawValue,
            "SP_CERT": configuration.spCertificate,
            "TIMESTAMP": String(unsignedParameters.timestamp.timeIntervalSince1970 * 1000)
        ]
        
        if let origin = unsignedParameters.origin?.absoluteString {
            parameters["ORIGIN"] = origin
        }
        if let rememberUserID = unsignedParameters.rememberUserID {
            parameters["REMEMBER_USERID"] = rememberUserID
        }
        if let rememberUserIDInitialStatus = unsignedParameters.rememberUserIDInitialStatus {
            parameters["REMEMBER_USERID_INITIAL_STATUS"] = rememberUserIDInitialStatus ? "TRUE": "FALSE"
        }
        
        let sortedAlphabeticallyByKeys = parameters.sorted(by: { $0.key.lowercased() < $1.key.lowercased()} )
        return sortedAlphabeticallyByKeys
            .reduce(into: "") { result, parameter in
                result += "\(parameter.key)\(parameter.value)"
            }
    }
}


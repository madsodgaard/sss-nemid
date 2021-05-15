import Foundation
import Crypto

enum NemIDParameterSigningError: Error {
    case invalidData
}

struct NemIDParametersSigner {
    private let configuration: NemIDConfiguration
    
    public init(configuration: NemIDConfiguration) {
        self.configuration = configuration
    }
    
    /// Follows steps according to NemID documentation 3.2
    public func sign(_ parameters: NemIDUnsignedClientParameters) throws -> NemIDSignedClientParameters {
        // Step 1:
        let normalizedData = try [UInt8](normalizedParameters(parameters).utf8)
        let digest = SHA256.hash(data: normalizedData)
        
        // Step 2:
        let signer = RSASigner(key: configuration.privateKey)
        let signature = try signer.sign(normalizedData)
        
        // Step 3:
        let base64ParamsDigest = Data(digest).base64EncodedString()
        let base64SignedDigest = Data(signature).base64EncodedString()
        
        // Step 4:
        return try NemIDSignedClientParameters(
            clientFlow: parameters.clientFlow,
            language: parameters.language,
            origin: parameters.origin,
            rememberUserID: parameters.rememberUserID,
            rememberUserIDInitialStatus: parameters.rememberUserIDInitialStatus,
            spCert: configuration.spCertificate.toBase64EncodedDER(),
            timestamp: parameters.timestamp,
            digestSignature: base64SignedDigest,
            paramsDigest: base64ParamsDigest,
            enableAwaitingAppApprovalEvent: parameters.enableAwaitingAppApprovalEvent
        )
    }
    
    /// Returns a normalized string of the parameters, as described in the NemID documentation.
    ///
    /// 1. The parameters are sorted alphabetically by name. The sorting is case-insensitive.
    /// 2. Each parameter is concatenated to the result string as an alternating sequence of name and value
    private func normalizedParameters(_ unsignedParameters: NemIDUnsignedClientParameters) throws -> String {
        var parameters: [String: String] = try [
            "CLIENTFLOW": unsignedParameters.clientFlow.rawValue,
            "LANGUAGE": unsignedParameters.language.rawValue,
            "SP_CERT": configuration.spCertificate.toBase64EncodedDER(),
            "TIMESTAMP": String(Int(unsignedParameters.timestamp.timeIntervalSince1970 * 1000))
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
        
        if let enableAwaitingAppApprovalEvent = unsignedParameters.enableAwaitingAppApprovalEvent {
            parameters["ENABLE_AWAITING_APP_APPROVAL_EVENT"] = enableAwaitingAppApprovalEvent ? "TRUE" : "FALSE"
        }
        
        let sortedAlphabeticallyByKeys = parameters.sorted(by: { $0.key.lowercased() < $1.key.lowercased()} )
        return sortedAlphabeticallyByKeys
            .reduce(into: "") { result, parameter in
                result += "\(parameter.key)\(parameter.value)"
            }
    }
}


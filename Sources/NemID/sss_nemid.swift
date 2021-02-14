import Foundation
import Crypto
import CNemIDBoringSSL

enum NemID {}

enum ClientParametersClientFlow: String, Encodable {
    /// 2 factor OCES login
    case ocesLogin2
}
enum ClientParametersClientLanguage: String, Encodable {
    case danish = "DA"
    case english = "EN"
    case greenlandic = "KL"
}

protocol NemIDClientParameters {
    /// Determines which NemID flow to start
    var clientFlow: ClientParametersClientFlow { get }
    /// Client language
    var language: ClientParametersClientLanguage { get }
    /// The origin of the Service Provider site which will send parameters to the NemID JavaScript client.
    /// The NemID JavaScript client will abort with APP001 or APP007 if a postMessage command is received from any other origin.
    var origin: URL? { get }
    /// Base64 encoded token returned from the client when the user chooses to remember his user id.
    /// At next login/signing this parameter must be specified in order to enable the remember user id functionality.
    var rememberUserID: String? { get }
    /// Indicates that the “Remember userid checkbox” should not be initially checked.
    /// This is only relevant in responsive mode and when REMEMBER_USERID is also set.
    var rememberUserIDInitialStatus: Bool? { get }
    /// Base64 encoded DER representation of the certificate used for identifying the OCES Service Provider
    var SPCert: String { get }
    /// Current time when generating parameters. The timestamp parameter is converted to UTC and must match the NemID server time.
    /// NemID accepts timestamps within the boundaries of +-3 minutes.
    var timestamp: Date { get }
}

extension NemIDClientParameters {
    /// Returns a normalized string of the parameters, as described in the NemID documentation.
    ///
    /// 1. The parameters are sorted alphabetically by name. The sorting is case-insensitive.
    /// 2. Each parameter is concatenated to the result string as an alternating sequence of name and value
    var normalized: String {
        var parameters: [String: String] = [
            "CLIENTFLOW": self.clientFlow.rawValue,
            "LANGUAGE": self.language.rawValue,
            "SP_CERT": self.SPCert,
            "TIMESTAMP": String(self.timestamp.timeIntervalSince1970 * 1000)
        ]
        
        if let origin = self.origin?.absoluteString { parameters["ORIGIN"] = origin }
        if let rememberUserID = self.rememberUserID { parameters["REMEMBER_USERID"] = rememberUserID }
        if let rememberUserIDInitialStatus = self.rememberUserIDInitialStatus { parameters["REMEMBER_USERID_INITIAL_STATUS"] = rememberUserIDInitialStatus ? "TRUE": "FALSE" }
        
        let sortedAlphabeticallyByKeys = parameters.sorted(by: { $0.key.lowercased() < $1.key.lowercased()} )
        return sortedAlphabeticallyByKeys
            .reduce(into: "") { result, parameter in
                result += "\(parameter.key)\(parameter.value)"
            }
    }
}

struct UnsignedClientParameters: NemIDClientParameters {
    var clientFlow: ClientParametersClientFlow
    var language: ClientParametersClientLanguage
    var origin: URL?
    var rememberUserID: String?
    var rememberUserIDInitialStatus: Bool?
    var SPCert: String
    var timestamp: Date
}

extension NemID {
    struct SignedClientParameters: NemIDClientParameters, Encodable {
        let clientFlow: ClientParametersClientFlow
        let language: ClientParametersClientLanguage
        let origin: URL?
        let rememberUserID: String?
        let rememberUserIDInitialStatus: Bool?
        let SPCert: String
        let timestamp: Date
        /// Base64 encoded RSA signature of the calculated parameter digest.
        let digestSignature: String
        /// Base64 encoded representation of the calculated parameter digest.
        let paramsDigest: String
        
        enum CodingKeys: String, CodingKey {
            case clientFlow = "CLIENTFLOW"
            case language = "LANGUAGE"
            case origin = "ORIGIN"
            case rememberUserID = "REMEMBER_USERID"
            case rememberUserIDInitialStatus = "REMEMBER_USERID_INITIAL_STATUS"
            case SPCert = "SP_CERT"
            case timestamp = "TIMESTAMP"
            case digestSignature = "DIGEST_SIGNATURE"
            case paramsDigest = "PARAMS_DIGEST"
        }
    }
}

extension NemID {
    enum ParameterSigningError: Error {
        case invalidData
    }
    
    struct ParameterSigner {
        func sign(_ parameters: UnsignedClientParameters) throws -> SignedClientParameters {
            guard let normalizedData = parameters.normalized.data(using: .utf8) else { throw ParameterSigningError.invalidData }
            let digest = SHA256.hash(data: normalizedData)
            let base64ParamsDigest = Data(digest).base64EncodedString()
            
            return SignedClientParameters(
                clientFlow: parameters.clientFlow,
                language: parameters.language,
                origin: parameters.origin,
                rememberUserID: parameters.rememberUserID,
                rememberUserIDInitialStatus: parameters.rememberUserIDInitialStatus,
                SPCert: parameters.SPCert,
                timestamp: parameters.timestamp,
                digestSignature: "",
                paramsDigest: base64ParamsDigest)
        }
    }
}


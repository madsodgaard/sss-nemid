import Foundation

/// This is the type which the SP-server will send to NemID client as JSON.
public struct NemIDSignedClientParameters: NemIDClientParameters, Encodable {
    public let clientFlow: NemIDClientParametersClientFlow
    public let language: NemIDClientParametersClientLanguage
    public let origin: URL?
    public let rememberUserID: String?
    public let rememberUserIDInitialStatus: Bool?
    public let SPCert: String
    public let timestamp: Date
    /// Base64 encoded RSA256 signature of the calculated parameter digest.
    public let digestSignature: String
    /// Base64 encoded representation of the calculated parameter digest.
    public let paramsDigest: String
    
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
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(clientFlow, forKey: .clientFlow)
        try container.encode(language, forKey: .language)
        try container.encode(origin, forKey: .origin)
        try container.encode(rememberUserID, forKey: .rememberUserID)
        try container.encode(rememberUserIDInitialStatus, forKey: .rememberUserIDInitialStatus)
        try container.encode(timestamp.timeIntervalSince1970 * 1000, forKey: .timestamp)
        try container.encode(digestSignature, forKey: .digestSignature)
        try container.encode(paramsDigest, forKey: .paramsDigest)
    }
}

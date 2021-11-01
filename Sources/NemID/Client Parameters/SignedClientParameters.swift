import Foundation

/// This is the type which the SP-server will send to NemID client as JSON.
public struct NemIDSignedClientParameters: NemIDClientParameters, Codable {
    public let clientFlow: NemIDClientParametersClientFlow
    public let language: NemIDClientParametersClientLanguage
    public let origin: URL?
    public let rememberUserID: String?
    public let rememberUserIDInitialStatus: Bool?
    public let spCert: String
    public let timestamp: Date
    /// Base64 encoded RSA256 signature of the calculated parameter digest.
    public let digestSignature: String
    /// Base64 encoded representation of the calculated parameter digest.
    public let paramsDigest: String
    public let enableAwaitingAppApprovalEvent: Bool?
    
    enum CodingKeys: String, CodingKey {
        case clientFlow = "CLIENTFLOW"
        case language = "LANGUAGE"
        case origin = "ORIGIN"
        case rememberUserID = "REMEMBER_USERID"
        case rememberUserIDInitialStatus = "REMEMBER_USERID_INITIAL_STATUS"
        case spCert = "SP_CERT"
        case timestamp = "TIMESTAMP"
        case digestSignature = "DIGEST_SIGNATURE"
        case paramsDigest = "PARAMS_DIGEST"
        case enableAwaitingAppApprovalEvent = "ENABLE_AWAITING_APP_APPROVAL_EVENT"
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(clientFlow, forKey: .clientFlow)
        try container.encode(language, forKey: .language)
        try container.encodeIfPresent(origin, forKey: .origin)
        try container.encodeIfPresent(rememberUserID, forKey: .rememberUserID)
        try container.encodeIfPresent(rememberUserIDInitialStatus?.nemIDRepresentation, forKey: .rememberUserIDInitialStatus)
        try container.encode(spCert, forKey: .spCert)
        try container.encode(String(Int(timestamp.timeIntervalSince1970 * 1000)), forKey: .timestamp)
        try container.encode(digestSignature, forKey: .digestSignature)
        try container.encode(paramsDigest, forKey: .paramsDigest)
        try container.encodeIfPresent(enableAwaitingAppApprovalEvent?.nemIDRepresentation, forKey: .enableAwaitingAppApprovalEvent)
    }
}

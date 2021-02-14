import Foundation

struct NemIDSignedClientParameters: NemIDClientParameters, Encodable {
    let clientFlow: NemIDClientParametersClientFlow
    let language: NemIDClientParametersClientLanguage
    let origin: URL?
    let rememberUserID: String?
    let rememberUserIDInitialStatus: Bool?
    let SPCert: String
    let timestamp: Date
    /// Base64 encoded RSA256 signature of the calculated parameter digest.
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

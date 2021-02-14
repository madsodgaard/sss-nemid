import Foundation

struct NemIDUnsignedClientParameters: NemIDClientParameters {
    var clientFlow: NemIDClientParametersClientFlow
    var language: NemIDClientParametersClientLanguage
    var origin: URL?
    var rememberUserID: String?
    var rememberUserIDInitialStatus: Bool?
    var SPCert: String
    var timestamp: Date
}

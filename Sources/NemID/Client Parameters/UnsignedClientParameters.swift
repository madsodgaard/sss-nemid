import Foundation

public struct NemIDUnsignedClientParameters: NemIDClientParameters {
    public let clientFlow: NemIDClientParametersClientFlow
    public let language: NemIDClientParametersClientLanguage
    public let origin: URL?
    public let rememberUserID: String?
    public let rememberUserIDInitialStatus: Bool?
    public let timestamp: Date
    
    public init(
        clientFlow: NemIDClientParametersClientFlow,
        language: NemIDClientParametersClientLanguage,
        origin: URL?,
        rememberUserID: String?,
        rememberUserIDInitialStatus: Bool?,
        timestamp: Date
    ) {
        self.clientFlow = clientFlow
        self.language = language
        self.origin = origin
        self.rememberUserID = rememberUserID
        self.rememberUserIDInitialStatus = rememberUserIDInitialStatus
        self.timestamp = timestamp
    }
}

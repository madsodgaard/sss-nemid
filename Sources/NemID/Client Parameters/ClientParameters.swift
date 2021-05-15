import Foundation

public enum NemIDClientParametersClientFlow: String, Codable {
    /// 2 factor OCES login
    case ocesLogin2 = "OCESLOGIN2"
}

public enum NemIDClientParametersClientLanguage: String, Codable {
    case danish = "DA"
    case english = "EN"
    case greenlandic = "KL"
}

public protocol NemIDClientParameters {
    /// Determines which NemID flow to start
    var clientFlow: NemIDClientParametersClientFlow { get }
    
    /// Client language
    var language: NemIDClientParametersClientLanguage { get }
    
    /// The origin of the Service Provider site which will send parameters to the NemID JavaScript client.
    /// The NemID JavaScript client will abort with APP001 or APP007 if a postMessage command is received from any other origin.
    var origin: URL? { get }
    
    /// Base64 encoded token returned from the client when the user chooses to remember his user id.
    /// At next login/signing this parameter must be specified in order to enable the remember user id functionality.
    var rememberUserID: String? { get }
    
    /// Indicates that the “Remember userid checkbox” should not be initially checked.
    /// This is only relevant in responsive mode and when REMEMBER_USERID is also set.
    var rememberUserIDInitialStatus: Bool? { get }
    
    /// Current time when generating parameters. The timestamp parameter is converted to UTC and must match the NemID server time.
    /// NemID accepts timestamps within the boundaries of +-3 minutes.
    var timestamp: Date { get }
    
    /// Indicates if the JS an awaiting app client should send out app approval event
    /// The event can be caught outside the JS client using the event handler set-up from section 3.3 where command will be “AwaitingAppApproval
    ///
    /// TRUE => Enable awaiting client should send out app approval event.
    /// Any other value or unset (default) => No event
    var enableAwaitingAppApprovalEvent: Bool? { get }
}

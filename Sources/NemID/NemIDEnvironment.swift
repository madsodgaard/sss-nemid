import Foundation

public struct NemIDEnvironment {
    let pidCPRMatchEndpoint: String
    
    init(pidCPRMatchEndpoint: String) {
        self.pidCPRMatchEndpoint = pidCPRMatchEndpoint
    }
    
    public static let production = NemIDEnvironment(
        pidCPRMatchEndpoint: "https://pidws.certifikat.dk/pid_serviceprovider_server/pidxml/"
    )
    
    public static let preproduction = NemIDEnvironment(
        pidCPRMatchEndpoint: "https://pidws.pp.certifikat.dk/pid_serviceprovider_server/pidxml/"
    )
}

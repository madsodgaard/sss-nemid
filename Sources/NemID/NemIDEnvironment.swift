import Foundation

public struct NemIDEnvironment {
    let pidCPRMatchEndpoint: String
    
    init(pidCPRMatchEndpoint: String) {
        self.pidCPRMatchEndpoint = pidCPRMatchEndpoint
    }
    
    static let production = NemIDEnvironment(
        pidCPRMatchEndpoint: "https://pidws.certifikat.dk/pid_serviceprovider_server/pidxml/"
    )
    
    static let preproduction = NemIDEnvironment(
        pidCPRMatchEndpoint: "https://pidws.pp.certifikat.dk/pid_serviceprovider_server/pidxml/"
    )
}

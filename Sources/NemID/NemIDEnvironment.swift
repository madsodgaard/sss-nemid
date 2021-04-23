import Foundation

public struct NemIDEnvironment {
    /// The endpoint for the PID-CPR match service.
    let pidCPRMatchEndpoint: String
    /// The SHA256 fingerprint of the OCES root certificate.
    let ocesCertificateFingerprint: String
    
    init(pidCPRMatchEndpoint: String, ocesCertificateFingerprint: String) {
        self.pidCPRMatchEndpoint = pidCPRMatchEndpoint
        self.ocesCertificateFingerprint = ocesCertificateFingerprint
    }
    
    public static let production = NemIDEnvironment(
        pidCPRMatchEndpoint: "https://pidws.certifikat.dk/pid_serviceprovider_server/pidxml/",
        ocesCertificateFingerprint: "92d8092ee77bc9208f0897dc05271894e63ef27933ae537fb983eef0eae3eec8"
    )
    
    public static let preproduction = NemIDEnvironment(
        pidCPRMatchEndpoint: "https://pidws.pp.certifikat.dk/pid_serviceprovider_server/pidxml/",
        ocesCertificateFingerprint: "0e2fd1fda36a4bf3995e28619704d60e3382c91e44a2b458ab891316380b1d50"
    )
}

import Foundation

public struct NemIDConfiguration {
    /// The certificate of the OCES service-provider.
    public let spCertificate: NemIDX509Certificate
    /// The private key for the OCES service provider.
    public let privateKey: NemIDRSAKey
    /// The service provider ID supplied by NemID (also known as SPID)
    public let serviceProviderID: String
    /// The NemID environment to use
    public let environment: NemIDEnvironment
    
    public init(
        spCertificate: NemIDX509Certificate,
        privateKey: NemIDRSAKey,
        serviceProviderID: String,
        environment: NemIDEnvironment
    ) {
        self.spCertificate = spCertificate
        self.privateKey = privateKey
        self.serviceProviderID = serviceProviderID
        self.environment = environment
    }
}

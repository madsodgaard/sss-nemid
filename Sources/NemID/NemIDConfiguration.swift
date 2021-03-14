import Foundation

public struct NemIDConfiguration {
    /// The certificate of the OCES service-provider as a Base64 encoded DER.
    public let spCertificate: String
    /// The service provider ID supplied by NemID (also known as SPID)
    public let serviceProviderID: String
    /// The NemID environment to use
    public let environment: NemIDEnvironment
    
    public init(
        spCertificate: String,
        serviceProviderID: String,
        environment: NemIDEnvironment
    ) {
        self.spCertificate = spCertificate
        self.serviceProviderID = serviceProviderID
        self.environment = environment
    }
}

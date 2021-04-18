import Foundation

public struct NemIDConfiguration {
    /// The certificate of the OCES service-provider.
    public let spCertificate: X509Certificate
    /// The private key for the OCES service provider.
    public let privateKey: RSAKey
    /// The service provider ID supplied by NemID (also known as SPID)
    public let serviceProviderID: String
    /// The NemID environment to use
    public let environment: NemIDEnvironment
    
    public init(
        spCertificate: X509Certificate,
        privateKey: RSAKey,
        serviceProviderID: String,
        environment: NemIDEnvironment
    ) {
        self.spCertificate = spCertificate
        self.privateKey = privateKey
        self.serviceProviderID = serviceProviderID
        self.environment = environment
    }
}

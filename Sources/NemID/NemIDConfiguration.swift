import Foundation

public struct NemIDConfiguration {
    /// The certificate of the OCES service-provider as a Base64 encoded DER.
    public let spCertificate: String
    
    public init(spCertificate: String) {
        self.spCertificate = spCertificate
    }
}

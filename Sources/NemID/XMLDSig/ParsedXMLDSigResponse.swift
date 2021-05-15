import Foundation

struct ParsedXMLDSigResponse {
    /// Returns the <SignatureValue> value as base64 encoded string
    let signatureValue: String
    /// Returns the <SignedInfo> element as XML data
    let signedInfo: Data
    /// Returns the reference digest value as base64 encoded string.
    let referenceDigestValue: String
    /// Returns the <Object> body where the id is ToBeSigned as XML data.
    let objectToBeSigned: Data
    /// Returns an array of X509 certificates
    let x509Certificates: [String]
    
    func verifiedCertificateChain() throws -> CertificateChain {
        let certificates = try x509Certificates
            .map { base64DerCertificate -> NemIDX509Certificate in
                guard let decoded = Data(base64Encoded: base64DerCertificate, options: .ignoreUnknownCharacters) else {
                    throw CertificateChainError.failedToDecodeCertificate
                }
                return try NemIDX509Certificate(der: decoded)
            }
        
        guard certificates.count == 3 else {
            throw CertificateChainError.unexpectedCertificateCount(certificates.count)
        }
        
        // Count how many times each certificate is used as subject or issuer.
        let certificatesUsageCount = certificates.reduce(into: [[UInt8]: Int]()) { res, certificate in
            guard let subject = certificate.subject,
                  let issuer = certificate.issuer
            else { return }
            res[issuer] = (res[issuer] ?? 0) + 1
            res[subject] = (res[subject] ?? 0) + 1
        }
        
        // Leaf certificate should only have one usage (as subject).
        guard let leafCertificateName = certificatesUsageCount.first(where: { $0.value == 1 })?.key,
              let leafCertificate = certificates.first(where: { $0.subject == leafCertificateName })
        else { throw CertificateChainError.failedToLocateLeafCertificate }
        
        // Intermediate should be used twice (subject and issuer of leaf)
        guard let intermediateCertificateName = certificatesUsageCount.first(where: { $0.value == 2 })?.key,
              let intermediateCertificate = certificates.first(where: { $0.subject == intermediateCertificateName })
        else { throw CertificateChainError.failedToLocateIntermediateCertificate }
        
        // Intermediate should be used three time (subject, issuer of intermediate and self)
        guard let rootCertificateName = certificatesUsageCount.first(where: { $0.value == 3 })?.key,
              let rootCertificate = certificates.first(where: { $0.subject == rootCertificateName })
        else { throw CertificateChainError.failedToLocateRootCertificate }
        
        // Verify issuers (chain) is correct
        guard leafCertificate.issuer == intermediateCertificate.subject else { throw CertificateChainError.leafIssuerWasNotIntermediate }
        guard intermediateCertificate.issuer == rootCertificate.subject else { throw CertificateChainError.intermediateIssuerWasNotRoot }
        guard rootCertificate.issuer == rootCertificate.subject else { throw CertificateChainError.rootWasNotSelfSigned }
        
        return CertificateChain(
            root: rootCertificate,
            intermediate: intermediateCertificate,
            leaf: leafCertificate
        )
    }
}

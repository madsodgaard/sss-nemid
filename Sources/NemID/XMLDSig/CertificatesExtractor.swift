import Foundation

struct CertificateChain {
    let root: X509Certificate
    let intermediate: X509Certificate
    let leaf: X509Certificate
}

enum CertificatesExtractorError: Error {
    case failedToDecodeCertificate
    case unexpectedCertificateCount(Int)
    case failedToLocateLeafCertificate
    case failedToLocateIntermediateCertificate
    case failedToLocateRootCertificate
    case leafIssuerWasNotIntermediate
    case intermediateIssuerWasNotRoot
    case rootWasNotSelfSigned
}

struct CertificatesExtractor {
    func extract(from xml: ParsedXMLDSigResponse) throws -> CertificateChain {
        let certificates = try xml.x509Certificates
            .map { base64DerCertificate -> X509Certificate in
                guard let decoded = Data(base64Encoded: base64DerCertificate, options: .ignoreUnknownCharacters) else {
                    throw CertificatesExtractorError.failedToDecodeCertificate
                }
                return try X509Certificate(der: decoded)
            }
        
        guard certificates.count == 3 else { throw CertificatesExtractorError.unexpectedCertificateCount(certificates.count) }

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
        else { throw CertificatesExtractorError.failedToLocateLeafCertificate }
        
        // Intermediate should be used twice (subject and issuer of leaf)
        guard let intermediateCertificateName = certificatesUsageCount.first(where: { $0.value == 2 })?.key,
              let intermediateCertificate = certificates.first(where: { $0.subject == intermediateCertificateName })
        else { throw CertificatesExtractorError.failedToLocateIntermediateCertificate }
        
        // Intermediate should be used three time (subject, issuer of intermediate and self)
        guard let rootCertificateName = certificatesUsageCount.first(where: { $0.value == 3 })?.key,
              let rootCertificate = certificates.first(where: { $0.subject == rootCertificateName })
        else { throw CertificatesExtractorError.failedToLocateRootCertificate }
        
        // Verify issuers (chain) is correct
        guard leafCertificate.issuer == intermediateCertificate.subject else { throw CertificatesExtractorError.leafIssuerWasNotIntermediate }
        guard intermediateCertificate.issuer == rootCertificate.subject else { throw CertificatesExtractorError.intermediateIssuerWasNotRoot }
        guard rootCertificate.issuer == rootCertificate.subject else { throw CertificatesExtractorError.rootWasNotSelfSigned }
        
        return CertificateChain(
            root: rootCertificate,
            intermediate: intermediateCertificate,
            leaf: leafCertificate)
    }
}


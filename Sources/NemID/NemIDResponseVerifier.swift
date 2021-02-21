import Foundation
import SwiftyXMLParser
import Crypto
@_implementationOnly import CNemIDBoringSSL

enum NemIDResponseVerifierError: Error {
    case failedToExtractSignedInfo
    case failedToExtractReferenceDigest
    case failedToExtractObjectToBeSigned
    case failedToExtractSignatureValue
    case digestDidNotMatchSignedObject
    case signedInfoWasNotSignedByCertificate
    case certificateWasNotSignedByCorrectCertificate
    case failedToExtractCertificateDates
    case certificateIsOutsideValidTime
}

struct NemIDResponseVerifier {
    let xmlParser: XMLDSigParser
    
    /// Verifies a response from a NemID client flow such as logging in
    ///
    /// Does the checks in respect to the NemID documentation p. 34:
    /// - Extract the certficiates from XMLDSig
    /// - Validate the signature on XMLDSig
    /// - Validate the certificate and identify CA as OCES throughout the chain
    /// - Check that the certificate has not expired
    /// - Check that the certficate has not been revoked
    ///
    /// - Parameters:
    ///     - response: The XML as a `String` received from the client.
    func verify(_ response: String) throws {
        let parsedResponse = try xmlParser.parse(response)
        // Extract certificate chain.
        let certificates = try CertificatesExtractor().extract(from: parsedResponse)
        
        // Validate XML signature with leaf certificate
        try validateXMLSignature(parsedResponse, withCert: certificates.leaf)
        
        // Validate certificate chain
        try validateCertificateChain(certificates)
        
        // TODO: Verify that certificate has not been revoked (OCSP)
    }
    
    private func validateCertificateChain(_ chain: CertificateChain) throws {
        // TODO: Verify that leaf certificate has digitalSignature key usage
        
        for certificate in chain {
            // Verify certificate times.
            guard let notAfter = certificate.notAfter(),
                  let notBefore = certificate.notBefore()
            else {
                throw NemIDResponseVerifierError.failedToExtractCertificateDates
            }
            guard notAfter < Date() && notBefore > Date() else { throw NemIDResponseVerifierError.certificateIsOutsideValidTime }
        }
        
        // TODO: Verify that intermediate and root has cA constraint
        
        // TODO: Verify that intermediate and root has keyCertSign usage
        
        // Verify the actual chain signing.
        guard try chain.leaf.isSignedBy(by: chain.intermediate),
              try chain.intermediate.isSignedBy(by: chain.root),
              try chain.root.isSignedBy(by: chain.root)
        else {
            throw NemIDResponseVerifierError.certificateWasNotSignedByCorrectCertificate
        }
        
        // TODO: Verify that root certificate is a trusted OCES certificate.
    }
    
    /// Verifies the signed element in the xml response
    private func validateXMLSignature(_ response: ParsedXMLDSigResponse, withCert certificate: X509Certificate) throws {
        guard let signedInfoC14N = response.signedInfo.data(using: .utf8)?.C14N()
        else { throw NemIDResponseVerifierError.failedToExtractSignedInfo }
        
        guard let referenceDigestBase64Decoded = Data(base64Encoded: response.referenceDigestValue)
        else { throw NemIDResponseVerifierError.failedToExtractReferenceDigest }
        
        guard let objectToBeSignedC14N = response.objectToBeSigned.data(using: .utf8)?.C14N()
        else { throw NemIDResponseVerifierError.failedToExtractObjectToBeSigned }
        
        guard let signatureValueBase64Decoded = Data(base64Encoded: response.signatureValue)
        else { throw NemIDResponseVerifierError.failedToExtractSignatureValue }
        
        // Verify reference object digest was made from ToBeSigned object.
        guard SHA256.hash(data: objectToBeSignedC14N) == referenceDigestBase64Decoded else { throw NemIDResponseVerifierError.digestDidNotMatchSignedObject }
        
        // Verify that signedInfo was signed with certificate
        let signer = RSASigner(key: try certificate.publicKey())
        guard try signer.verify(signatureValueBase64Decoded, signs: signedInfoC14N) else { throw NemIDResponseVerifierError.signedInfoWasNotSignedByCertificate }
    }
}

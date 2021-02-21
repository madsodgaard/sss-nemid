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
    case certificateWasNotSignedByPublicKey
    case failedToExtractCertificateDates
    case certificateIsOutsideValidTime
}

struct NemIDResponseVerifier {
    let xmlParser: XMLDSigParser
    
    /// Verifies a response from a NemID client flow such as logging in
    ///
    /// Does the checks in respect to the NemID documentation p. 34:
    /// 1. Extract the certficiates from XMLDSig
    /// 2. Validate the signature on XMLDSig
    /// 3. Validate the certificate and identify CA as OCES throughout the chain
    /// 4. Check that the certificate has not expired
    /// 5. Check that the certficate has not been revoked
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
    }
    
    private func validateCertificateChain(_ chain: CertificateChain) throws {
        let allCertificates = [chain.root, chain.intermediate, chain.leaf]
        
        for certificate in allCertificates {
            // Verify certificate times.
            guard let notAfter = certificate.notAfter(), let notBefore = certificate.notBefore() else { throw NemIDResponseVerifierError.failedToExtractCertificateDates }
            guard notAfter < Date() && notBefore > Date() else { throw NemIDResponseVerifierError.certificateIsOutsideValidTime }
        }
        
        // Verify the actual chain signing.
        guard try chain.leaf.isSignedBy(by: chain.intermediate),
              try chain.intermediate.isSignedBy(by: chain.root),
              try chain.root.isSignedBy(by: chain.root)
        else {
            throw NemIDResponseVerifierError.certificateWasNotSignedByPublicKey
        }
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

import Foundation
import SwiftyXMLParser
import Crypto
@_implementationOnly import CNemIDBoringSSL

struct DefaultNemIDResponseHandler: NemIDResponseHandler {
    private let xmlParser: XMLDSigParser
    private let certificateExtractor: CertificateExtrator
    
    public init(xmlParser: XMLDSigParser, certificateExtractor: CertificateExtrator) {
        self.xmlParser = xmlParser
        self.certificateExtractor = certificateExtractor
    }
    
    func verifyAndExtractUser(from response: String) throws -> NemIDUser {
        let parsedResponse = try xmlParser.parse(response)
        // Extract certificate chain.
        let certificates = try certificateExtractor.extract(from: parsedResponse)
        
        // Validate XML signature with leaf certificate
        try validateXMLSignature(parsedResponse, withCert: certificates.leaf)
        
        // Validate certificate chain
        try validateCertificateChain(certificates)
        
        // TODO: Verify that certificate has not been revoked (OCSP)
        #warning("todo")
        
        return try NemIDUser(from: certificates.leaf)
    }
    
    private func validateCertificateChain(_ chain: CertificateChain) throws {
        // Verify that leaf certificate has digitalSignature key usage
        guard chain.leaf.hasKeyUsage(.digitalSignature) else { throw NemIDResponseHandlerError.leafDidNotHaveDigitalSignatureKeyUsage }
        
        // Verify certificate times.
        for certificate in chain {
            guard let notAfter = certificate.notAfter(),
                  let notBefore = certificate.notBefore()
            else {
                throw NemIDResponseHandlerError.failedToExtractCertificateDates
            }
            guard notAfter < Date() && notBefore > Date() else { throw NemIDResponseHandlerError.certificateIsOutsideValidTime }
        }
        
        #warning("Path len validation???")
        
        // Verify that intermediate and root has cA constraint
        guard chain.root.hasCAFlag() && chain.intermediate.hasCAFlag() else { throw NemIDResponseHandlerError.issuerDidNotHaveCAFlag }
        
        // Verify that intermediate and root has keyCertSign usage
        guard chain.intermediate.hasKeyUsage(.keyCertSign) && chain.root.hasKeyUsage(.keyCertSign) else { throw NemIDResponseHandlerError.issuerDidNotHaveKeyCertSignKeyUsage }
        
        // Verify the actual chain signing.
        guard try chain.leaf.isSignedBy(by: chain.intermediate),
              try chain.intermediate.isSignedBy(by: chain.root),
              try chain.root.isSignedBy(by: chain.root)
        else {
            throw NemIDResponseHandlerError.certificateWasNotSignedByCorrectCertificate
        }
        
        // Verify that root certificate is a trusted OCES certificate.
        #warning("todo")
    }
    
    /// Verifies the signed element in the xml response
    private func validateXMLSignature(_ response: ParsedXMLDSigResponse, withCert certificate: X509Certificate) throws {
        guard let signedInfoC14N = response.signedInfo.data(using: .utf8)?.C14N() else {
            throw NemIDResponseHandlerError.failedToExtractSignedInfo
        }
        guard let referenceDigestBase64Decoded = Data(base64Encoded: response.referenceDigestValue) else {
            throw NemIDResponseHandlerError.failedToExtractReferenceDigest
        }
        guard let objectToBeSignedC14N = response.objectToBeSigned.data(using: .utf8)?.C14N() else {
            throw NemIDResponseHandlerError.failedToExtractObjectToBeSigned
        }
        guard let signatureValueBase64Decoded = Data(base64Encoded: response.signatureValue) else {
            throw NemIDResponseHandlerError.failedToExtractSignatureValue
        }
        
        // Verify reference object digest was made from ToBeSigned object.
        guard SHA256.hash(data: objectToBeSignedC14N) == referenceDigestBase64Decoded else { throw NemIDResponseHandlerError.digestDidNotMatchSignedObject }
        
        // Verify that signedInfo was signed with certificate
        let signer = RSASigner(key: try certificate.publicKey())
        guard try signer.verify(signatureValueBase64Decoded, signs: signedInfoC14N) else { throw NemIDResponseHandlerError.signedInfoWasNotSignedByCertificate }
    }
}

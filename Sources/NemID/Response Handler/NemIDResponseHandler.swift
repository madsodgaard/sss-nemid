import Foundation
import Crypto
import NIO
@_implementationOnly import CNemIDBoringSSL

#warning("if something fails it might be releated to this:")
/*
 //remember to skip the first byte it is the number of unused bits and it is always 0 for keys and certificates from nodes-php
 */
struct NemIDResponseHandler {
    private let xmlParser: XMLDSigParser
    private let certificateExtractor: CertificateExtrator
    private let ocspClient: OCSPClient
    private let eventLoop: EventLoop
    
    init(xmlParser: XMLDSigParser, certificateExtractor: CertificateExtrator, ocspClient: OCSPClient, eventLoop: EventLoop) {
        self.xmlParser = xmlParser
        self.certificateExtractor = certificateExtractor
        self.ocspClient = ocspClient
        self.eventLoop = eventLoop
    }
    
    /// Verifies a response from a NemID client flow such as logging in and extratcs the user as `NemIDUser`
    ///
    /// Does the checks in respect to the NemID documentation p. 34:
    /// - Extract the certficiates from XMLDSig
    /// - Validate the signature on XMLDSig
    /// - Validate the certificate and identify CA as OCES throughout the chain
    /// - Check that the certificate has not expired
    /// - Check that the certficate has not been revoked
    ///
    /// - Parameters:
    ///     - response: The XML as XML data received from the client.
    /// - Returns: A `EventLoopFuture` containg the verified certificate user as `NemIDUser`.
    func verifyAndExtractUser(fromXML xmlData: [UInt8]) -> EventLoopFuture<NemIDUser> {
        do {
            let parsedResponse = try xmlParser.parse(xmlData)
            // Extract certificate chain.
            let certificates = try certificateExtractor.extract(from: parsedResponse)
            
            // Validate XML signature with leaf certificate
            try validateXMLSignature(parsedResponse, wasSignedBy: certificates.leaf)
            
            // Validate certificate chain
            try validateCertificateChain(certificates)
            
            // Verify that certificate has not been revoked (OCSP)
            let ocspRequest = try OCSPRequest(certificate: certificates.leaf, issuer: certificates.intermediate)
            return ocspClient
                .send(request: ocspRequest)
                .flatMapThrowing { response in
                    try validateOCSPResponse(response, chain: certificates)
                    return try NemIDUser(from: certificates.leaf)
                }
        } catch {
            return eventLoop.makeFailedFuture(error)
        }
    }
    
    private func validateOCSPResponse(_ response: OCSPResponse, chain: CertificateChain) throws {
        // Check response status
        guard response.responseStatus == .successful else {
            throw NemIDResponseHandlerError.ocspRequestWasNotSuccessful
        }
        guard let basicResponse = response.basicOCSPResponse else {
            throw NemIDResponseHandlerError.ocspBasicResponseIsNotPresent
        }
        
        // Validate that signature is tbsResponseData signed by accompanying certificate
        guard let ocspCertificate = basicResponse.certs.first else {
            throw NemIDResponseHandlerError.ocspCertificateNotFoundInResponse
        }
        let signer = RSASigner(key: try ocspCertificate.publicKey())
        guard try signer.verify(basicResponse.signature, signs: basicResponse.tbsResponseData.derBytes) else {
            throw NemIDResponseHandlerError.ocspSignatureWasNotSignedByCertificate
        }
        
        // Validate that accompanying certificate was signed by issuer.
        guard try ocspCertificate.isSignedBy(by: chain.intermediate) else {
            throw NemIDResponseHandlerError.ocspCertificateWasNotSignedByIssuer
        }
        
        // Validate certificate recovation status
        guard let certResponse = basicResponse.tbsResponseData.responses.first else {
            throw NemIDResponseHandlerError.ocspCertificateResponseNotPresent
        }
        guard certResponse.certStatus == .good else {
            throw NemIDResponseHandlerError.ocspCertificateStatusIsNotGood
        }
        
        // Check hash algorithm
        guard certResponse.certID.hashAlgorithm == .sha256 else {
            throw NemIDResponseHandlerError.ocspCertificateWrongHashAlgorithm
        }
        
        // Check hash name, key hash and serial number are the ones we sent in the request.
        try chain.leaf.withSerialNumber { serialNumber in
            var ptr: UnsafeMutablePointer<UInt8>?
            ptr = nil
            let leafSerialNumberSize = CNemIDBoringSSL_BN_bn2bin(serialNumber, ptr)
            let leafSerialNumberBytes = [UInt8](UnsafeMutableBufferPointer(start: ptr, count: leafSerialNumberSize))
            guard certResponse.certID.serialNumber == leafSerialNumberBytes else { fatalError() }
        }
        guard chain.intermediate.hashedPublicKey == certResponse.certID.issuerKeyHash else { fatalError() }
        guard chain.intermediate.hashedSubject == certResponse.certID.issuerNameHash else { fatalError() }
        
        // Check OCSP revocation dates
        guard certResponse.nextUpdate >= Date() && certResponse.thisUpdate <= Date() else {
            throw NemIDResponseHandlerError.ocspResponseIsOutsideAllowedTime
        }
        
        // Check OCSP signing key usage
        guard ocspCertificate.hasExtendedKeyUsage(.ocspSigning) else {
            throw NemIDResponseHandlerError.ocspCertificateDidNotHaveOCSPSigningExtendedKeyUsage
        }
        
        // Check OCSP extension
        guard !ocspCertificate.hasOCSPNoCheckExtension() else {
            throw NemIDResponseHandlerError.ocspCertificateHasNoCheckExtension
        }
    }
    
    private func validateCertificateChain(_ chain: CertificateChain) throws {
        // Verify that leaf certificate has digitalSignature key usage
        guard chain.leaf.hasKeyUsage(.digitalSignature) else {
            throw NemIDResponseHandlerError.leafDidNotHaveDigitalSignatureKeyUsage
        }
        
        for certificate in chain {
            // Verify dates
            guard let notAfter = certificate.notAfter(),
                  let notBefore = certificate.notBefore()
            else {
                throw NemIDResponseHandlerError.failedToExtractCertificateDates
            }
            guard notAfter < Date() && notBefore > Date() else {
                throw NemIDResponseHandlerError.certificateIsOutsideValidTime
            }
        }
        
        // Verify that intermediate and root has cA constraint
        guard chain.root.hasCAFlag() && chain.intermediate.hasCAFlag() else {
            throw NemIDResponseHandlerError.issuerDidNotHaveCAFlag
        }
        
        // Verify that intermediate and root has keyCertSign usage
        guard chain.intermediate.hasKeyUsage(.keyCertSign) && chain.root.hasKeyUsage(.keyCertSign) else {
            throw NemIDResponseHandlerError.issuerDidNotHaveKeyCertSignKeyUsage
        }
        
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
    private func validateXMLSignature(_ response: ParsedXMLDSigResponse, wasSignedBy certificate: X509Certificate) throws {
        guard let signedInfoC14N = response.signedInfo.C14N() else {
            throw NemIDResponseHandlerError.failedToExtractSignedInfo
        }
        guard let referenceDigestBase64Decoded = Data(base64Encoded: response.referenceDigestValue) else {
            throw NemIDResponseHandlerError.failedToExtractReferenceDigest
        }
        guard let objectToBeSignedC14N = response.objectToBeSigned.C14N() else {
            throw NemIDResponseHandlerError.failedToExtractObjectToBeSigned
        }
        guard let signatureValueBase64Decoded = Data(base64Encoded: response.signatureValue) else {
            throw NemIDResponseHandlerError.failedToExtractSignatureValue
        }
        
        // Verify reference object digest was made from ToBeSigned object.
        guard SHA256.hash(data: objectToBeSignedC14N) == referenceDigestBase64Decoded else {
            throw NemIDResponseHandlerError.digestDidNotMatchSignedObject
        }
        
        // Verify that signedInfo was signed with certificate
        let signer = RSASigner(key: try certificate.publicKey())
        guard try signer.verify([UInt8](signatureValueBase64Decoded), signs: signedInfoC14N) else {
            throw NemIDResponseHandlerError.signedInfoWasNotSignedByCertificate
        }
    }
}

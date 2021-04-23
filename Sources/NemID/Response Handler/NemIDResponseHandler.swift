import Foundation
import Crypto
import NIO
@_implementationOnly import CNemIDBoringSSL

struct NemIDResponseHandler {
    private let xmlParser: XMLDSigParser
    private let ocspClient: OCSPClient
    private let eventLoop: EventLoop
    private let configuration: NemIDConfiguration
    
    init(xmlParser: XMLDSigParser, ocspClient: OCSPClient, eventLoop: EventLoop, configuration: NemIDConfiguration) {
        self.xmlParser = xmlParser
        self.ocspClient = ocspClient
        self.eventLoop = eventLoop
        self.configuration = configuration
    }
    
    /// Verifies a response from a NemID client flow such as logging in and extratcs the user as `NemIDUser`
    /// Will also check for if the response is a NemID error and return `NemIDError`
    ///
    /// Does the checks in respect to the NemID documentation p. 34:
    /// - Extract the certficiates from XMLDSig
    /// - Validate the signature on XMLDSig
    /// - Validate the certificate and identify CA as OCES throughout the chain
    /// - Check that the certificate has not expired
    /// - Check that the certficate has not been revoked
    ///
    /// - Parameters:
    ///     - response: Base64 encoded response data received from the NemID client.
    /// - Returns: A `EventLoopFuture` containg the verified certificate user as `NemIDUser`.
    func verifyAndExtractUser(from response: Data) -> EventLoopFuture<NemIDUser> {
        do {
            guard let base64DecodedData = Data(base64Encoded: response) else {
                throw NemIDResponseHandlerError.failedToDecodeResponseAsBase64
            }
            
            // Check if the response is an error.
            if let responseString = String(data: base64DecodedData, encoding: .utf8),
               let clientError = NemIDResponseError(rawValue: responseString)
            {
                throw clientError
            }
            
            // Parse the response as a successful XML message.
            let parsedResponse = try xmlParser.parse([UInt8](base64DecodedData))
            
            // Extract certificate chain.
            let certificates = try parsedResponse.verifiedCertificateChain()
            
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
            throw OCSPValidationError.requestWasNotSuccessful
        }
        guard let basicResponse = response.basicOCSPResponse else {
            throw OCSPValidationError.basicResponseIsNotPresent
        }
        
        // Validate that signature is tbsResponseData signed by accompanying certificate
        guard let ocspCertificate = basicResponse.certs.first else {
            throw OCSPValidationError.certificateNotFoundInResponse
        }
        
        // Validate OCSP signature was made from tbsResponseData.
        let signer = RSASigner(key: try ocspCertificate.publicKey(), hashAlgorithm: basicResponse.signatureAlgorithm.hashAlgorithm)
        guard try signer.verify(basicResponse.signature, signs: basicResponse.tbsResponseData.derBytes) else {
            throw OCSPValidationError.signatureWasNotSignedByCertificate
        }
        
        // Validate that accompanying certificate was signed by issuer.
        guard try ocspCertificate.isSignedBy(by: chain.intermediate) else {
            throw OCSPValidationError.certificateWasNotSignedByIssuer
        }
        
        // Validate certificate recovation status
        guard let certResponse = basicResponse.tbsResponseData.responses.first else {
            throw OCSPValidationError.certificateResponseNotPresent
        }
        guard certResponse.certStatus == .good else {
            throw OCSPValidationError.certificateStatusIsNotGood
        }
        
        // Check hash algorithm
        guard certResponse.certID.hashAlgorithm == .sha256 else {
            throw OCSPValidationError.certificateWrongHashAlgorithm
        }
        
        // Check hash name, key hash and serial number are the ones we sent in the request.
        try chain.leaf.withSerialNumber { serialNumber in
            var output = [UInt8](repeating: 0, count: numericCast(CNemIDBoringSSL_BN_num_bytes(serialNumber)))
            let leafSerialNumberSize = CNemIDBoringSSL_BN_bn2bin(serialNumber, &output)
            let leafSerialNumberBytes = [UInt8](output[0..<Int(leafSerialNumberSize)])
            guard certResponse.certID.serialNumber == leafSerialNumberBytes else {
                throw OCSPValidationError.serialNumberDidNotMatchRequest
            }
        }
        guard chain.intermediate.hashedPublicKey == certResponse.certID.issuerKeyHash else {
            throw OCSPValidationError.issuerKeyHashDidNotMatchRequest
        }
        guard chain.intermediate.hashedSubject == certResponse.certID.issuerNameHash else {
            throw OCSPValidationError.issuerNameHashDidNotMatchRequest
        }
        
        // Check OCSP revocation dates
        guard certResponse.nextUpdate >= Date() && certResponse.thisUpdate <= Date() else {
            throw OCSPValidationError.responseIsOutsideAllowedTime
        }
        
        // Check OCSP signing key usage
        guard ocspCertificate.hasExtendedKeyUsage(.ocspSigning) else {
            throw OCSPValidationError.certificateDidNotHaveOCSPSigningExtendedKeyUsage
        }
        
        // Check OCSP NoCheck extension is present (should be null)
        guard ocspCertificate.hasOCSPNoCheckExtension() else {
            throw OCSPValidationError.certificateNoCheckExtensionNotFound
        }
    }
    
    private func validateCertificateChain(_ chain: CertificateChain) throws {
        // Verify that leaf certificate has digitalSignature key usage
        guard chain.leaf.hasKeyUsage(.digitalSignature) else {
            throw CertificateChainValidationError.leafDidNotHaveDigitalSignatureKeyUsage
        }
        
        // Verify dates
        for certificate in chain {
            guard Date() < certificate.notAfter() && Date() > certificate.notBefore() else {
                throw CertificateChainValidationError.certificateIsOutsideValidTime
            }
        }
        
        // Verify that intermediate and root has cA constraint
        guard chain.root.hasCAFlag() && chain.intermediate.hasCAFlag() else {
            throw CertificateChainValidationError.issuerDidNotHaveCAFlag
        }
        
        // Verify that intermediate and root has keyCertSign usage
        guard chain.intermediate.hasKeyUsage(.keyCertSign) && chain.root.hasKeyUsage(.keyCertSign) else {
            throw CertificateChainValidationError.issuerDidNotHaveKeyCertSignKeyUsage
        }
        
        // Verify the actual chain signing.
        guard try chain.leaf.isSignedBy(by: chain.intermediate),
              try chain.intermediate.isSignedBy(by: chain.root),
              try chain.root.isSignedBy(by: chain.root)
        else {
            throw CertificateChainValidationError.certificateWasNotSignedByCorrectCertificate
        }
        
        // Verify that root certificate is a trusted OCES certificate.
        guard try chain.root.fingerprint() == configuration.environment.ocesCertificateFingerprint else {
            throw CertificateChainValidationError.failedToVerifyRootAsOCES
        }
    }
    
    /// Verifies the signed element in the xml response
    private func validateXMLSignature(_ response: ParsedXMLDSigResponse, wasSignedBy certificate: NemIDX509Certificate) throws {
        guard let signedInfoC14N = response.signedInfo.C14N() else {
            throw XMLValidationError.failedToExtractSignedInfo
        }
        guard let referenceDigestBase64Decoded = Data(base64Encoded: response.referenceDigestValue) else {
            throw XMLValidationError.failedToExtractReferenceDigest
        }
        guard let objectToBeSignedC14N = response.objectToBeSigned.C14N() else {
            throw XMLValidationError.failedToExtractObjectToBeSigned
        }
        guard let signatureValueBase64Decoded = Data(base64Encoded: response.signatureValue, options: .ignoreUnknownCharacters) else {
            throw XMLValidationError.failedToExtractSignatureValue
        }
        
        // Verify reference object digest was made from ToBeSigned object.
        guard SHA256.hash(data: objectToBeSignedC14N) == referenceDigestBase64Decoded else {
            throw XMLValidationError.digestDidNotMatchSignedObject
        }
        
        // Verify that signedInfo was signed with certificate
        let signer = RSASigner(key: try certificate.publicKey())
        guard try signer.verify([UInt8](signatureValueBase64Decoded), signs: signedInfoC14N) else {
            throw XMLValidationError.signedInfoWasNotSignedByCertificate
        }
    }
}

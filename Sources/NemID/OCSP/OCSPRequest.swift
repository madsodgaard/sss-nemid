import Foundation
import Crypto
@_implementationOnly import CNemIDBoringSSL

struct OCSPRequest {
    enum OCSPRequestError: Error {
        case failedToGetIssuerPublicKey
        case failedToGetIssuerSubject
        case failedToGetSerialNumber
        case failedToGenerateRequest
        case failedToRetrieveOCSPURL
    }
    
    /// The OCSP request ASN1 as DER encoded bytes.
    let requestDER: [UInt8]
    /// The OCSP server endpoint (fetched from leaf)
    let endpoint: String
    
    /// Builds an OCSP request
    /// - Parameters:
    ///     - certificate: The `X509Certificate` the requset is for
    ///     - issuer: The `X509Certificate` issuer of `certificate`
    /// - Returns: The OCSP request bytes DER-encoded.
    init(certificate: NemIDX509Certificate, issuer: NemIDX509Certificate) throws {
        // Hash issuer name and public key
        guard let issuerSubjectSHA256 = issuer.hashedSubject else {
            throw OCSPRequestError.failedToGetIssuerSubject
        }
        guard let publicKeySHA256 = issuer.hashedPublicKey else {
            throw OCSPRequestError.failedToGetIssuerPublicKey
        }
        
        // Create OCSPRequest ASN1 sequence
        var cbb = CBB()
        guard CNemIDBoringSSL_CBB_init(&cbb, 0) == 1 else { throw OCSPRequestError.failedToGenerateRequest }
        defer { CNemIDBoringSSL_CBB_cleanup(&cbb) }
        
        var ocspRequest = CBB()
        guard CNemIDBoringSSL_CBB_add_asn1(&cbb, &ocspRequest, CBS_ASN1_SEQUENCE) == 1 else {
            throw OCSPRequestError.failedToGenerateRequest
        }
        
        // Create TBSRequest ASN1 sequence
        var tbsRequest = CBB()
        guard CNemIDBoringSSL_CBB_add_asn1(&ocspRequest, &tbsRequest, CBS_ASN1_SEQUENCE) == 1 else {
            throw OCSPRequestError.failedToGenerateRequest
        }
        
        // Create requester list ASN1 sequence
        var requesterList = CBB()
        guard CNemIDBoringSSL_CBB_add_asn1(&tbsRequest, &requesterList, CBS_ASN1_SEQUENCE) == 1 else {
            throw OCSPRequestError.failedToGenerateRequest
        }
        
        // Create request ASN1 sequence
        var request = CBB()
        guard CNemIDBoringSSL_CBB_add_asn1(&requesterList, &request, CBS_ASN1_SEQUENCE) == 1 else {
            throw OCSPRequestError.failedToGenerateRequest
        }
        
        // Create CertID ASN1 sequence
        var certID = CBB()
        guard CNemIDBoringSSL_CBB_add_asn1(&request, &certID, CBS_ASN1_SEQUENCE) == 1 else {
            throw OCSPRequestError.failedToGenerateRequest
        }
        
        // Set the algorithm of CertID to SHA256.
        var algorithm = CBB()
        guard CNemIDBoringSSL_CBB_add_asn1(&certID, &algorithm, CBS_ASN1_SEQUENCE) == 1 else {
            throw OCSPRequestError.failedToGenerateRequest
        }
        guard CNemIDBoringSSL_OBJ_nid2cbb(&algorithm, NID_sha256) == 1 else {
            throw OCSPRequestError.failedToGenerateRequest
        }
        
        // Set issuerNameHash
        guard CNemIDBoringSSL_CBB_add_asn1_octet_string(&certID, issuerSubjectSHA256, issuerSubjectSHA256.count) == 1 else {
            throw OCSPRequestError.failedToGenerateRequest
        }
        
        // Set issuerKeyHash
        guard CNemIDBoringSSL_CBB_add_asn1_octet_string(&certID, publicKeySHA256, publicKeySHA256.count) == 1 else {
            throw OCSPRequestError.failedToGenerateRequest
        }
        
        // Set serial number
        try certificate.withSerialNumber { serialNumber in
            guard CNemIDBoringSSL_BN_marshal_asn1(&certID, serialNumber) == 1 else { throw OCSPRequestError.failedToGenerateRequest }
        }
        
        // Get OCSP request as DER-encoded data.
        var out: UnsafeMutablePointer<UInt8>?
        var length = 0
        guard CNemIDBoringSSL_CBB_finish(&cbb, &out, &length) == 1 else { throw OCSPRequestError.failedToGenerateRequest }
        guard let derPtr = out else { throw OCSPRequestError.failedToGenerateRequest }
        defer { CNemIDBoringSSL_OPENSSL_free(derPtr) }
        
        // Extract OCSP endpoint from certificate
        // STACK_OF(OPENSSL_STRING)
        guard let ocspStringStack = CNemIDBoringSSL_X509_get1_ocsp(certificate.ref) else {
            throw OCSPRequestError.failedToRetrieveOCSPURL
        }
        defer { CNemIDBoringSSL_sk_OPENSSL_STRING_free(ocspStringStack) }
        guard let ocspString = CNemIDBoringSSL_sk_OPENSSL_STRING_pop(ocspStringStack) else {
            throw OCSPRequestError.failedToRetrieveOCSPURL
        }
        
        // Initialize properties
        self.requestDER = [UInt8](UnsafeBufferPointer(start: derPtr, count: length))
        self.endpoint = String(cString: ocspString)
    }
}

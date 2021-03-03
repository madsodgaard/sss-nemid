import Foundation
import Crypto
@_implementationOnly import CNemIDBoringSSL

enum OCSPRequestBuilder {
    /// Builds an OCSP request
    /// - Parameters:
    ///     - certificate: The `X509Certificate` the requset is for
    ///     - issuer: The `X509Certificate` issuer of `certificate`
    /// - Returns: The OCSP request bytes DER-encoded.
    #warning("Use errors instead of nil")
    static func build(certificate: X509Certificate, issuer: X509Certificate) -> [UInt8]? {
        // Extract public key from issuer
        // Should not be freed.
        guard let pubKeyASN1 = CNemIDBoringSSL_X509_get0_pubkey_bitstr(issuer.ref) else { return nil }
        
        // No need to copy data
        let pubKeyData = Data(bytesNoCopy: CNemIDBoringSSL_ASN1_STRING_data(pubKeyASN1), count: numericCast(CNemIDBoringSSL_ASN1_STRING_length(pubKeyASN1)), deallocator: .none)
        
        // Extract issuer subject
        guard let issuerSubject = issuer.subject else { return nil }
        
        // Hash issuer name and public key
        let issuerSubjectSHA256 = [UInt8](SHA256.hash(data: issuerSubject))
        let publicKeySHA256 = [UInt8](SHA256.hash(data: pubKeyData))
        
        // Get serial number
        guard let serialNumberASN1 = CNemIDBoringSSL_X509_get0_serialNumber(certificate.ref) else { return nil }

        // Create OCSPRequest ASN1 sequence
        var cbb = CBB()
        CNemIDBoringSSL_CBB_init(&cbb, 0)
        defer { CNemIDBoringSSL_CBB_cleanup(&cbb) }
        
        var ocspRequest = CBB()
        CNemIDBoringSSL_CBB_add_asn1(&cbb, &ocspRequest, CBS_ASN1_SEQUENCE)
        
        // Create TBSRequest ASN1 sequence
        var tbsRequest = CBB()
        CNemIDBoringSSL_CBB_add_asn1(&ocspRequest, &tbsRequest, CBS_ASN1_SEQUENCE)
        
        // Create requester list ASN1 sequence
        var requesterList = CBB()
        CNemIDBoringSSL_CBB_add_asn1(&tbsRequest, &requesterList, CBS_ASN1_SEQUENCE)
        
        // Create request ASN1 sequence
        var request = CBB()
        CNemIDBoringSSL_CBB_add_asn1(&requesterList, &request, CBS_ASN1_SEQUENCE)
        
        // Create CertID ASN1 sequence
        var certID = CBB()
        CNemIDBoringSSL_CBB_add_asn1(&request, &certID, CBS_ASN1_SEQUENCE)
        
        // Set the algorithm of CertID to SHA256.
        var algorithm = CBB()
        CNemIDBoringSSL_CBB_add_asn1(&certID, &algorithm, CBS_ASN1_SEQUENCE)
        CNemIDBoringSSL_OBJ_nid2cbb(&algorithm, NID_sha256)
        
        // Set issuerNameHash
        CNemIDBoringSSL_CBB_add_asn1_octet_string(&certID, issuerSubjectSHA256, issuerSubjectSHA256.count)
        // Set issuerKeyHash
        CNemIDBoringSSL_CBB_add_asn1_octet_string(&certID, publicKeySHA256, publicKeySHA256.count)
        // Set serial number
        
        var bn = BIGNUM()
        CNemIDBoringSSL_BN_init(&bn)
        CNemIDBoringSSL_ASN1_INTEGER_to_BN(serialNumberASN1, &bn)
        CNemIDBoringSSL_BN_marshal_asn1(&certID, &bn)
        CNemIDBoringSSL_BN_clear(&bn)
        
        // Get OCSP request as DER-encoded data.
        var out: UnsafeMutablePointer<UInt8>?
        var length = 0
        CNemIDBoringSSL_CBB_finish(&cbb, &out, &length)
        guard let derPtr = out else { return nil }
        let derBytes = [UInt8](UnsafeBufferPointer(start: derPtr, count: length))
        CNemIDBoringSSL_OPENSSL_free(derPtr)
        return derBytes
    }
}

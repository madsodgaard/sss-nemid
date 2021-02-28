import Foundation
import Crypto
@_implementationOnly import CNemIDSSL

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
        let pubKeyData = Data(buffer: UnsafeBufferPointer(start: pubKeyASN1.pointee.data, count: numericCast(pubKeyASN1.pointee.length)))
        
        // Extract issuer subject
        guard let issuerSubject = issuer.subject else { return nil }
        
        // Hash issuer name and public key
        let issuerSubjectSHA256 = [UInt8](SHA256.hash(data: issuerSubject))
        let publicKeySHA256 = [UInt8](SHA256.hash(data: pubKeyData))
        
        // Convert issuer name to ASN 1 string
        let issuerNameHashASN1String = CNemIDBoringSSL_ASN1_OCTET_STRING_new()
        defer { CNemIDBoringSSL_ASN1_OCTET_STRING_free(issuerNameHashASN1String) }
        guard CNemIDBoringSSL_ASN1_OCTET_STRING_set(issuerNameHashASN1String, issuerSubjectSHA256, numericCast(issuerSubjectSHA256.count)) == 1 else { return nil }
        
        // Convert issuer public key to ASN 1 string
        let issuerKeyHashASN1String = CNemIDBoringSSL_ASN1_OCTET_STRING_new()
        defer { CNemIDBoringSSL_ASN1_OCTET_STRING_free(issuerKeyHashASN1String) }
        guard CNemIDBoringSSL_ASN1_OCTET_STRING_set(issuerKeyHashASN1String, publicKeySHA256, numericCast(publicKeySHA256.count)) == 1 else { return nil }
        
        // Extract serial number from certificate and convert to ASN 1 string.
        let serialNumberASN1String = CNemIDBoringSSL_ASN1_STRING_new()
        defer { CNemIDBoringSSL_ASN1_STRING_free(serialNumberASN1String) }
        // Should not be freed.
        guard let serialNumber = CNemIDBoringSSL_X509_get0_serialNumber(certificate.ref) else { return nil }
        guard CNemIDBoringSSL_ASN1_STRING_copy(serialNumberASN1String, serialNumber) == 1 else { return nil }
        
        // Copy the values into an OCSP CertID sequence.
        guard let certID = OCSP_CERTID_new() else { return nil }
//        defer { OCSP_CERTID_free(certID) } // crashes for some reason?
        CNemIDBoringSSL_ASN1_STRING_copy(&certID.pointee.issuerKeyHash, issuerKeyHashASN1String)
        CNemIDBoringSSL_ASN1_STRING_copy(&certID.pointee.issuerNameHash, issuerNameHashASN1String)
        CNemIDBoringSSL_ASN1_STRING_copy(&certID.pointee.serialNumber, serialNumberASN1String)
        
        #warning("The original OpenSSL code frees the old pointers.")
        // https://github.com/openssl/openssl/blob/1708e3e85b4a86bae26860aa5d2913fc8eff6086/crypto/ocsp/ocsp_lib.c#L41
        // Set the algorithm of CertID to SHA256.
        guard let algorithm = CNemIDBoringSSL_X509_ALGOR_new() else { return nil }
        defer { CNemIDBoringSSL_X509_ALGOR_free(algorithm) }
        certID.pointee.hashAlgorithm.algorithm = UnsafeMutablePointer(mutating: CNemIDBoringSSL_OBJ_nid2obj(NID_sha256))
        
        // Some extra stuff that the OpenSSL library also did.
        guard let type = CNemIDBoringSSL_ASN1_TYPE_new() else { return nil }
        defer { CNemIDBoringSSL_ASN1_TYPE_free(type) }
        CNemIDBoringSSL_ASN1_TYPE_set(type, V_ASN1_NULL, nil)
        certID.pointee.hashAlgorithm.parameter = type
        
        // Initialize ONEREQ sequence.
        guard let oneReq = OCSP_ONEREQ_new() else { return nil }
        // OpenSSL code frees the original pointer.
        OCSP_CERTID_free(oneReq.pointee.reqCert)
        oneReq.pointee.reqCert = certID
        
        guard let reqInfo = OCSP_REQINFO_new() else { return nil }
        // defer { OCSP_REQINFO_free(reqInfo) } // also crashes?
        guard sk_OCSP_ONEREQ_push(reqInfo.pointee.requestList, oneReq) == 1 else { return nil }
        
        guard let request = OCSP_REQUEST_new() else { return nil }
        defer { OCSP_REQUEST_free(request) }
        request.pointee.tbsRequest = reqInfo.pointee
        
        guard let bio = CNemIDBoringSSL_BIO_new(CNemIDBoringSSL_BIO_s_mem()) else { return nil }
        defer { CNemIDBoringSSL_BIO_free(bio) }
        
        // Convert OCSP_REQUEST to DER-encoded data.
        var out: UnsafeMutablePointer<UInt8>?
        let length = i2d_OCSP_REQUEST(request, &out)
        print("DER length: \(length)")
        guard let derPointer = out else { return nil }
        let asn1Bytes = [UInt8](UnsafeBufferPointer(start: derPointer, count: Int(length)))
        CNemIDBoringSSL_OPENSSL_free(derPointer)
        
        print(Data(asn1Bytes).base64EncodedString())
        
        return asn1Bytes
    }
}

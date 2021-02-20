import Foundation
@_implementationOnly import CNemIDBoringSSL

enum X509CertificateError: Error {
    case failedToRetrievePublicKey
}

final class X509Certificate: BIOLoadable {
    /// Initialize a new certificate from a DER-encoded string
    convenience init(der string: String) throws {
        try self.init(der: [UInt8](string.utf8))
    }
    
    /// Initialize a new certificate from DER-encoded data.
    convenience init<Data>(der data: Data) throws where Data: DataProtocol {
        let x509 = try Self.load(pem: data) { bioPtr in
            return CNemIDBoringSSL_d2i_X509_bio(bioPtr, nil)
        }
        
        self.init(x509)
    }
    
    /// Extracts the public key as `RSAKey`
    func publicKey() throws -> RSAKey {
        let pubKey = CNemIDBoringSSL_X509_get_pubkey(self.ref)
        defer { CNemIDBoringSSL_EVP_PKEY_free(pubKey) }
        guard let rsaKey = CNemIDBoringSSL_EVP_PKEY_get1_RSA(pubKey) else {
            throw X509CertificateError.failedToRetrievePublicKey
        }
        return RSAKey(rsaKey)
    }
    
    /// Returns the subject as ASN.1/DER encoded bytes.
    var subject: [UInt8]? {
        let _subjectName = CNemIDBoringSSL_X509_get_subject_name(ref)
        
        var subjectNameBytes: UnsafeMutablePointer<UInt8>?
        let length = CNemIDBoringSSL_i2d_X509_NAME(_subjectName, &subjectNameBytes)
        
        guard let subjectNamePointer = subjectNameBytes else { return nil }
        let asn1Bytes = [UInt8](UnsafeBufferPointer(start: subjectNamePointer, count: Int(length)))
        CNemIDBoringSSL_OPENSSL_free(subjectNamePointer)
        return asn1Bytes
    }
    
    /// Returns the issuer as ASN.1/DER encoded bytes.
    var issuer: [UInt8]? {
        let _name = CNemIDBoringSSL_X509_get_issuer_name(ref)
        
        var nameBytes: UnsafeMutablePointer<UInt8>?
        let length = CNemIDBoringSSL_i2d_X509_NAME(_name, &nameBytes)
        
        guard let namePointer = nameBytes else { return nil }
        let asn1Bytes = [UInt8](UnsafeBufferPointer(start: namePointer, count: Int(length)))
        CNemIDBoringSSL_OPENSSL_free(namePointer)
        return asn1Bytes
    }
    //
    //    /// Returns the common name as UTF-8 encoded bytes.
    //    var commonName: [UInt8]? {
    //        let _subjectName = CNemIDBoringSSL_X509_get_subject_name(ref)
    //
    //        var lastIndex: Int32 = -1
    //        var nextIndex: Int32 = -1
    //        repeat {
    //            lastIndex = nextIndex
    //            nextIndex = CNemIDBoringSSL_X509_NAME_get_index_by_NID(_subjectName, NID_commonName, lastIndex)
    //        } while nextIndex >= 0
    //
    //        guard lastIndex >= 0 else { return nil }
    //        guard let nameData = CNemIDBoringSSL_X509_NAME_ENTRY_get_data(CNemIDBoringSSL_X509_NAME_get_entry(_subjectName, nextIndex)) else { return nil }
    //
    //        var encodedName: UnsafeMutablePointer<UInt8>? = nil
    //        let stringLength = CNemIDBoringSSL_ASN1_STRING_to_UTF8(&encodedName, nameData)
    //
    //        guard let namePointer = encodedName else { return nil }
    //        let bytes = [UInt8](UnsafeBufferPointer(start: namePointer, count: Int(stringLength)))
    //        CNemIDBoringSSL_OPENSSL_free(namePointer)
    //        return bytes
    //    }
    
    var ref: UnsafeMutablePointer<X509> {
        _ref.assumingMemoryBound(to: X509.self)
    }
    
    let _ref: UnsafeMutableRawPointer
    
    private init(_ ref: UnsafeMutablePointer<X509>) {
        self._ref = UnsafeMutableRawPointer(ref)
    }
    
    deinit {
        CNemIDBoringSSL_X509_free(ref)
    }
}

extension X509Certificate: Equatable {
    static func ==(_ lhs: X509Certificate, _ rhs: X509Certificate) -> Bool {
        CNemIDBoringSSL_X509_cmp(lhs.ref, rhs.ref) == 0
    }
}

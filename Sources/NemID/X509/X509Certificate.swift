import Foundation
@_implementationOnly import CNemIDBoringSSL

enum X509CertificateError: Error {
    case failedToRetrievePublicKey
}

final class X509Certificate: BIOLoadable {
    /// Used for formatting the `notBefore`and `notAfter` date formats to Swift `Date`
    private lazy var dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = .init(identifier: "en-US")
        formatter.dateFormat = "MMM dd HH:mm:SS yyyy ZZZZ"
        return formatter
    }()
    
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
        try withPublicKey { key in
            guard let rsaKey = CNemIDBoringSSL_EVP_PKEY_get1_RSA(key) else {
                throw X509CertificateError.failedToRetrievePublicKey
            }
            return RSAKey(rsaKey)
        }
    }
    
    /// Verifies that `self` was signed with `signer`'s private key.
    func isSignedBy(by signer: X509Certificate) throws -> Bool {
        try signer.withPublicKey { pubKey in
            CNemIDBoringSSL_X509_verify(self.ref, pubKey) == 1
        }
    }
    
    /// Returns the certificate notBefore as a `Date`
    func notBefore() -> Date? {
        guard let asn1Time = CNemIDBoringSSL_X509_get0_notBefore(self.ref) else { return nil }
        guard let bio = CNemIDBoringSSL_BIO_new(CNemIDBoringSSL_BIO_s_mem()) else { return nil }
        defer { CNemIDBoringSSL_BIO_free(bio) }
        
        guard CNemIDBoringSSL_ASN1_TIME_print(bio, asn1Time) == 1 else { return nil }
        
        var _bytesPtr: UnsafeMutablePointer<Int8>?
        let availableBytes = CNemIDBoringSSL_BIO_get_mem_data(bio, &_bytesPtr)
        guard let bytesPtr = _bytesPtr else { return nil }
        let data = Data(buffer: UnsafeBufferPointer(start: bytesPtr, count: availableBytes))
        
        guard let utf8String = String(data: data, encoding: .utf8),
              let date = dateFormatter.date(from: utf8String)
        else { return nil }
        
        return date
    }
    
    /// Returns the certificate notAfter as a `Date`
    func notAfter() -> Date? {
        guard let asn1Time = CNemIDBoringSSL_X509_get0_notAfter(self.ref) else { return nil }
        guard let bio = CNemIDBoringSSL_BIO_new(CNemIDBoringSSL_BIO_s_mem()) else { return nil }
        defer { CNemIDBoringSSL_BIO_free(bio) }
        
        guard CNemIDBoringSSL_ASN1_TIME_print(bio, asn1Time) == 1 else { return nil }
        
        var _bytesPtr: UnsafeMutablePointer<Int8>?
        let availableBytes = CNemIDBoringSSL_BIO_get_mem_data(bio, &_bytesPtr)
        guard let bytesPtr = _bytesPtr else { return nil }
        let data = Data(buffer: UnsafeBufferPointer(start: bytesPtr, count: availableBytes))
        
        guard let utf8String = String(data: data, encoding: .utf8),
              let date = dateFormatter.date(from: utf8String)
        else { return nil }
        
        return date
    }
    
    /// Returns a `Bool` indicating whether this certificate has the "CA" constraint flag set.
    func hasCAFlag() -> Bool {
        let flags = CNemIDBoringSSL_X509_get_extension_flags(self.ref)
        return Int32(flags) & EXFLAG_CA == EXFLAG_CA
    }
    
    /// Check if this certificate has a specific `KeyUsage`
    func hasKeyUsage(_ usage: KeyUsage) -> Bool {
        let keyUsage = CNemIDBoringSSL_X509_get_key_usage(self.ref)
        return Int32(keyUsage) & usage.value == usage.value
    }
    
    /// Returns a pointer to the public key, which is only valid for the lifetime of the closure
    func withPublicKey<T>(_ handler: (UnsafeMutablePointer<EVP_PKEY>?) throws -> T) throws -> T {
        guard let pubKey = CNemIDBoringSSL_X509_get_pubkey(self.ref) else { throw X509CertificateError.failedToRetrievePublicKey }
        defer { CNemIDBoringSSL_EVP_PKEY_free(pubKey) }
        return try handler(pubKey)
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
    
    /// Returns the common name as UTF-8 encoded `String`.
    var subjectCommonName: String? {
        subjectNameComponentAsUT8(.commonName)
    }
    
    /// Returns the DN serial number as a UTF-8 encoded `String`
    var subjectSerialNumber: String? {
        subjectNameComponentAsUT8(.serialNumber)
    }
    
    private func subjectNameComponentAsUT8(_ component: NameComponent) -> String? {
        let _subjectName = CNemIDBoringSSL_X509_get_subject_name(ref)
        
        var lastIndex: CInt = -1
        var nextIndex: CInt = -1
        repeat {
            lastIndex = nextIndex
            nextIndex = CNemIDBoringSSL_X509_NAME_get_index_by_NID(_subjectName, component.value, lastIndex)
        } while nextIndex >= 0
        
        guard lastIndex >= 0 else { return nil }
        guard let nameData = CNemIDBoringSSL_X509_NAME_ENTRY_get_data(CNemIDBoringSSL_X509_NAME_get_entry(_subjectName, lastIndex)) else {
            return nil
        }
        
        var encodedName: UnsafeMutablePointer<UInt8>? = nil
        let stringLength = CNemIDBoringSSL_ASN1_STRING_to_UTF8(&encodedName, nameData)
        
        guard let namePointer = encodedName else { return nil }
        let bytes = [UInt8](UnsafeBufferPointer(start: namePointer, count: Int(stringLength)))
        CNemIDBoringSSL_OPENSSL_free(namePointer)
        return String(data: Data(bytes), encoding: .utf8)
    }
    
    var ref: UnsafeMutablePointer<X509> {
        _ref.assumingMemoryBound(to: X509.self)
    }
    
    private let _ref: UnsafeMutableRawPointer
    
    private init(_ ref: UnsafeMutablePointer<X509>) {
        self._ref = UnsafeMutableRawPointer(ref)
    }
    
    deinit {
        CNemIDBoringSSL_X509_free(ref)
    }
}

// MARK: Equatable
extension X509Certificate: Equatable {
    static func ==(_ lhs: X509Certificate, _ rhs: X509Certificate) -> Bool {
        CNemIDBoringSSL_X509_cmp(lhs.ref, rhs.ref) == 0
    }
}

// MARK: - KeyUsage
extension X509Certificate {
    enum KeyUsage {
        case digitalSignature
        case keyCertSign
        
        var value: Int32 {
            switch self {
            case .digitalSignature:
                return KU_DIGITAL_SIGNATURE
            case .keyCertSign:
                return KU_KEY_CERT_SIGN
            }
        }
    }
}

// MARK: - NameComponent
extension X509Certificate {
    struct NameComponent {
        let value: Int32
        
        init(_ value: Int32) {
            self.value = value
        }
        
        static let commonName = NameComponent(NID_commonName)
        static let serialNumber = NameComponent(NID_serialNumber)
    }
}

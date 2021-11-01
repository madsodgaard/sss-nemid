import Foundation
@_implementationOnly import CNemIDBoringSSL

public final class NemIDRSAKey: BIOLoadable {
    public static func `private`(pem string: String) throws -> NemIDRSAKey {
        try .private(pem: [UInt8](string.utf8))
    }
    
    public static func `private`<Data>(pem data: Data) throws -> NemIDRSAKey
        where Data: DataProtocol
    {
        guard let privateKey = self.load(pem: data, { bio -> UnsafeMutablePointer<RSA> in
            CNemIDBoringSSL_PEM_read_bio_RSAPrivateKey(bio, nil, nil, nil)
        }) else { throw NemIDError.failedToLoadPrivateKey }
        
        return self.init(privateKey)
    }
    
    func toDERBytes() throws -> [UInt8] {
        return try self.withUnsafeDERCertificateBuffer { Array($0) }
    }
    
    private func withUnsafeDERCertificateBuffer<T>(_ body: (UnsafeRawBufferPointer) throws -> T) throws -> T {
        guard let bio = CNemIDBoringSSL_BIO_new(CNemIDBoringSSL_BIO_s_mem()) else {
            fatalError("Failed to malloc for a BIO handler")
        }
        defer { CNemIDBoringSSL_BIO_free(bio) }
        
        guard CNemIDBoringSSL_i2d_RSAPrivateKey_bio(bio, self.ref) == 1 else {
            throw NemIDX509CertificateError.failedToRetrieveDERRepresentation
        }
        
        var dataPtr: UnsafeMutablePointer<CChar>? = nil
        let length = CNemIDBoringSSL_BIO_get_mem_data(bio, &dataPtr)
        
        guard let bytes = dataPtr.map({ UnsafeRawBufferPointer(start: $0, count: length) }) else {
            fatalError("Failed to map bytes from a certificate")
        }
        
        return try body(bytes)
    }
    
    var ref: UnsafeMutablePointer<RSA> {
        _ref.assumingMemoryBound(to: RSA.self)
    }
    
    let _ref: UnsafeMutableRawPointer
    
    init(_ ref: UnsafeMutablePointer<RSA>) {
        self._ref = UnsafeMutableRawPointer(ref)
    }
    
    deinit {
        CNemIDBoringSSL_RSA_free(ref)
    }
}

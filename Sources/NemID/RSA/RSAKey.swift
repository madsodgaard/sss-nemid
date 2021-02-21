import Foundation
@_implementationOnly import CNemIDBoringSSL

public final class RSAKey: BIOLoadable {
    public static func `private`(pem string: String) throws -> RSAKey {
        try .private(pem: [UInt8](string.utf8))
    }
    
    public static func `private`<Data>(pem data: Data) throws -> RSAKey
    where Data: DataProtocol
    {
        let privateKey = try self.load(pem: data, { bio in
            CNemIDBoringSSL_PEM_read_bio_RSAPrivateKey(bio, nil, nil, nil)
        })
        
        return self.init(privateKey)
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

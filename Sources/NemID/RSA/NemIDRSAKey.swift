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

import Foundation
import CNemIDBoringSSL

final class RSAKey {
    public static func `private`<Data>(pem data: Data) throws -> RSAKey
    where Data: DataProtocol
    {
        let privateKey = try self.load(pem: data, { bio in
            CNemIDBoringSSL_PEM_read_bio_RSAPrivateKey(bio, nil, nil, nil)
        })
        
        return self.init(privateKey)
    }
    
    private static func load<Data, T>(pem data: Data, _ closure: (UnsafeMutablePointer<BIO>) -> T?) throws -> T
    where Data: DataProtocol
    {
        let bytes = data.copyBytes()
        let bio = CNemIDBoringSSL_BIO_new_mem_buf(bytes, numericCast(bytes.count))
        defer { CNemIDBoringSSL_BIO_free(bio) }
        
        guard let bioPtr = bio, let result = closure(bioPtr) else {
            fatalError()
        }
        return result
    }
    
    let key: UnsafeMutablePointer<RSA>
    
    init(_ key: UnsafeMutablePointer<RSA>) {
        self.key = key
    }
    
    deinit {
        CNemIDBoringSSL_RSA_free(key)
    }
}

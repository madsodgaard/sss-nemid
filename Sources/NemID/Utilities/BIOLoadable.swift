import Foundation
@_implementationOnly import CNemIDBoringSSL

protocol BIOLoadable { }

enum BIOLoadableError: Error {
    case failedToLoadBIO
}

extension BIOLoadable {
    static func load<Data, T>(pem data: Data, _ closure: (UnsafeMutablePointer<BIO>) -> T?) throws -> T
    where Data: DataProtocol
    {
        let bytes = data.copyBytes()
        let bio = CNemIDBoringSSL_BIO_new_mem_buf(bytes, numericCast(bytes.count))
        defer { CNemIDBoringSSL_BIO_free(bio) }
        
        guard let bioPtr = bio, let result = closure(bioPtr) else {
            throw BIOLoadableError.failedToLoadBIO
        }
        return result
    }
}

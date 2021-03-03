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
        precondition(data.regions.count <= 1, "There is no such thing as data that has discontiguous regions")
        guard let region = data.regions.first else { throw BIOLoadableError.failedToLoadBIO }
        
        return try region.withUnsafeBytes { ptr in
            let bio = CNemIDBoringSSL_BIO_new_mem_buf(ptr.baseAddress, numericCast(ptr.count))
            guard let bioPtr = bio else { throw BIOLoadableError.failedToLoadBIO }
            defer { CNemIDBoringSSL_BIO_free(bio) }
            guard let result = closure(bioPtr) else { throw BIOLoadableError.failedToLoadBIO }
            return result
        }
    }
}

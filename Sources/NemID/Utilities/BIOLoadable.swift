import Foundation
@_implementationOnly import CNemIDBoringSSL

protocol BIOLoadable { }

extension BIOLoadable {
    static func load<Data, T>(pem data: Data, _ closure: (UnsafeMutablePointer<BIO>) throws -> T?) rethrows -> T?
        where Data: DataProtocol
    {
        precondition(data.regions.count <= 1, "There is no such thing as data that has discontiguous regions")
        guard let region = data.regions.first else { return nil }
        
        return try region.withUnsafeBytes { ptr in
            let bio = CNemIDBoringSSL_BIO_new_mem_buf(ptr.baseAddress, numericCast(ptr.count))!
            defer { CNemIDBoringSSL_BIO_free(bio) }
            return try closure(bio)
        }
    }
}

import Foundation
@_implementationOnly import CNemIDBoringSSL

enum HashAlgorithm {
    case sha1
    case sha256

    init?(nid: Int32) {
        switch nid {
        case NID_sha256: self = .sha256
        case NID_sha1: self = .sha1
        default: return nil
        }
    }
    
    var _boringPointer: OpaquePointer {
        switch self {
        case .sha1: return CNemIDBoringSSL_EVP_sha1()
        case .sha256: return CNemIDBoringSSL_EVP_sha256()
        }
    }
}

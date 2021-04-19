import Foundation
@_implementationOnly import CNemIDBoringSSL

enum SignatureAlgorithm {
    case sha256WithRSAEncryption
    case sha1WithRSAEncryption
    
    init?(nid: Int32) {
        switch nid {
        case NID_sha256WithRSAEncryption: self = .sha256WithRSAEncryption
        case NID_sha1WithRSAEncryption: self = .sha1WithRSAEncryption
        default: return nil
        }
    }
    
    var hashAlgorithm: HashAlgorithm {
        switch self {
        case .sha1WithRSAEncryption: return .sha1
        case .sha256WithRSAEncryption: return .sha256
        }
    }
}

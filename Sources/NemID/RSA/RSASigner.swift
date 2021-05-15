import Foundation
@_implementationOnly import CNemIDBoringSSL

enum RSASignerError: Error {
    case failedToSignDigest
    case failedToInitializeDigest
    case failedToUpdateDigest
    case failedToGetDigest
}

struct RSASigner {
    let key: NemIDRSAKey
    let hashAlgorithm: HashAlgorithm
    
    init(key: NemIDRSAKey, hashAlgorithm: HashAlgorithm = .sha256) {
        self.key = key
        self.hashAlgorithm = hashAlgorithm
    }
    
    func sign(_ plaintext: [UInt8]) throws -> [UInt8] {
        var signatureLength: UInt32 = 0
        var signature = [UInt8](repeating: 0, count: numericCast(CNemIDBoringSSL_RSA_size(key.ref)))
        
        let digest = try self.digest(plaintext)
        guard CNemIDBoringSSL_RSA_sign(
            CNemIDBoringSSL_EVP_MD_type(hashAlgorithm._boringPointer),
            digest,
            numericCast(digest.count),
            &signature,
            &signatureLength,
            key.ref
        ) == 1 else {
            throw RSASignerError.failedToSignDigest
        }
        
        return [UInt8](signature[0..<Int(signatureLength)])
    }
    
    func verify(_ signature: [UInt8], signs plaintext: [UInt8]) throws -> Bool {
        let digest = try self.digest(plaintext)
        return CNemIDBoringSSL_RSA_verify(
            CNemIDBoringSSL_EVP_MD_type(hashAlgorithm._boringPointer),
            digest,
            numericCast(digest.count),
            signature,
            numericCast(signature.count),
            self.key.ref
        ) == 1
    }
    
    private func digest(_ plaintext: [UInt8]) throws -> [UInt8] {
        let context = CNemIDBoringSSL_EVP_MD_CTX_new()
        defer { CNemIDBoringSSL_EVP_MD_CTX_free(context) }
        
        guard CNemIDBoringSSL_EVP_DigestInit_ex(context, hashAlgorithm._boringPointer, nil) == 1 else {
            throw RSASignerError.failedToInitializeDigest
        }
        
        guard CNemIDBoringSSL_EVP_DigestUpdate(context, plaintext, numericCast(plaintext.count)) == 1 else {
            throw RSASignerError.failedToUpdateDigest
        }
        
        var digestLength: UInt32 = 0
        var digest = [UInt8](repeating: 0, count: Int(EVP_MAX_MD_SIZE))
        guard CNemIDBoringSSL_EVP_DigestFinal_ex(context, &digest, &digestLength) == 1 else {
            throw RSASignerError.failedToGetDigest
        }
        
        return [UInt8](digest[0..<Int(digestLength)])
    }
}

import Foundation
@_implementationOnly import CNemIDBoringSSL

enum RSASignerError: Error {
    case failedToSignDigest
    case failedToInitializeDigest
    case failedToUpdateDigest
    case failedToGetDigest
}

public struct RSASigner {
    let key: RSAKey
    
    public init(key: RSAKey) {
        self.key = key
    }
    
    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8] where Plaintext: DataProtocol {
        var signatureLength: UInt32 = 0
        var signature = [UInt8](repeating: 0, count: Int(CNemIDBoringSSL_RSA_size(key.ref)))
        
        let digest = try self.digest(plaintext)
        guard CNemIDBoringSSL_RSA_sign(
            CNemIDBoringSSL_EVP_MD_type(CNemIDBoringSSL_EVP_sha256()),
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
    
    func verify<Signature, Plaintext>(
        _ signature: Signature,
        signs plaintext: Plaintext
    ) throws -> Bool
        where Signature: DataProtocol, Plaintext: DataProtocol
    {
        let digest = try self.digest(plaintext)
        let signature = signature.copyBytes()
        return CNemIDBoringSSL_RSA_verify(
            CNemIDBoringSSL_EVP_MD_type(CNemIDBoringSSL_EVP_sha256()),
            digest,
            numericCast(digest.count),
            signature,
            numericCast(signature.count),
            self.key.ref
        ) == 1
    }
    
    private func digest<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8] where Plaintext: DataProtocol {
        let context = CNemIDBoringSSL_EVP_MD_CTX_new()
        defer { CNemIDBoringSSL_EVP_MD_CTX_free(context) }
        
        guard CNemIDBoringSSL_EVP_DigestInit_ex(context, CNemIDBoringSSL_EVP_sha256(), nil) == 1 else {
            throw RSASignerError.failedToInitializeDigest
        }
        
        let bytes = plaintext.copyBytes()
        guard CNemIDBoringSSL_EVP_DigestUpdate(context, bytes, numericCast(bytes.count)) == 1 else {
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

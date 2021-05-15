import XCTest
@testable import NemID
@_implementationOnly import CNemIDBoringSSL

final class RSASignerTests: XCTestCase {
    func test_sign() throws {
        let plaintext = [UInt8]("hello".utf8)
        let signer = try RSASigner(key: .private(pem: TestHelper.rsaPrivateKey), hashAlgorithm: .sha256)
        let ciphertext = try signer.sign(plaintext)
        
        try XCTAssertTrue(signer.verify(ciphertext, signs: plaintext))
    }
}


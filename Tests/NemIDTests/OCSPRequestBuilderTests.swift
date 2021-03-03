import Foundation
import XCTest
@testable import NemID
@_implementationOnly import CNemIDBoringSSL

final class OCSPRequestBuilderTests: XCTestCase {
    func test_OCSP() throws {
        let certificate = try X509Certificate(der: Data(base64Encoded: TestCertificates.googleLeaf, options: .ignoreUnknownCharacters)!)
        let issuer = try X509Certificate(der: Data(base64Encoded: TestCertificates.googleIntermediate, options: .ignoreUnknownCharacters)!)
        let req = try OCSPRequestBuilder.build(certificate: certificate, issuer: issuer)
    }
}

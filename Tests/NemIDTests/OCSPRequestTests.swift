import Foundation
import XCTest
@testable import NemID
@_implementationOnly import CNemIDBoringSSL

final class OCSPRequestTests: XCTestCase {
    let certificate = try! X509Certificate(der: Data(base64Encoded: TestCertificates.googleLeaf, options: .ignoreUnknownCharacters)!)
    let issuer = try! X509Certificate(der: Data(base64Encoded: TestCertificates.googleIntermediate, options: .ignoreUnknownCharacters)!)
    
    func test_init_parsesOCSPEndpoint() throws {
        let request = try OCSPRequest(certificate: certificate, issuer: issuer)
        
        XCTAssertEqual(request.endpoint, "http://ocsp.pki.goog/gts1o1core")
    }
}

import XCTest
@testable import NemID

final class CertificateExtractorTests: XCTestCase {
    func test_extract_extractsChain() throws {
        let sut = DefaultCertificateExtractor()
        let response = ParsedXMLDSigResponse(
            signatureValue: "",
            signedInfo: Data(),
            referenceDigestValue: "",
            objectToBeSigned: Data(),
            x509Certificates: [
                TestCertificates.googleRoot,
                TestCertificates.googleIntermediate,
                TestCertificates.googleLeaf,
            ]
        )
        
        let chain = try sut.extract(from: response)
        try XCTAssertEqual(chain.root, X509Certificate(der: Data(base64Encoded: TestCertificates.googleRoot, options: .ignoreUnknownCharacters)!))
        try XCTAssertEqual(chain.intermediate, X509Certificate(der: Data(base64Encoded: TestCertificates.googleIntermediate, options: .ignoreUnknownCharacters)!))
        try XCTAssertEqual(chain.leaf, X509Certificate(der: Data(base64Encoded: TestCertificates.googleLeaf, options: .ignoreUnknownCharacters)!))
    }
}

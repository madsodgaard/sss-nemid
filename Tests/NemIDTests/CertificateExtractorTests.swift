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
                TestHelper.googleRoot,
                TestHelper.googleIntermediate,
                TestHelper.googleLeaf,
            ]
        )
        
        let chain = try sut.extract(from: response)
        try XCTAssertEqual(chain.root, NemIDX509Certificate(der: Data(base64Encoded: TestHelper.googleRoot, options: .ignoreUnknownCharacters)!))
        try XCTAssertEqual(chain.intermediate, NemIDX509Certificate(der: Data(base64Encoded: TestHelper.googleIntermediate, options: .ignoreUnknownCharacters)!))
        try XCTAssertEqual(chain.leaf, NemIDX509Certificate(der: Data(base64Encoded: TestHelper.googleLeaf, options: .ignoreUnknownCharacters)!))
    }
}

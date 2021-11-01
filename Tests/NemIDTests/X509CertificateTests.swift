import Foundation
import XCTest
@testable import NemID

final class X509CertificateTests: XCTestCase {
    func test_notBefore() throws {
        let certificate = try NemIDX509Certificate(der: Data(base64Encoded: TestHelper.googleRoot, options: .ignoreUnknownCharacters)!)
        // 15/12/2006 08:00:00 GMT
        XCTAssertEqual(certificate.notBefore(), Date(timeIntervalSince1970: 1166169600))
    }
    
    func test_notAfter() throws {
        let certificate = try NemIDX509Certificate(der: Data(base64Encoded: TestHelper.googleRoot, options: .ignoreUnknownCharacters)!)
        // 15/12/2021 08:00:00 GMT
        XCTAssertEqual(certificate.notAfter(), Date(timeIntervalSince1970: 1639555200))
    }
    
    func test_hasCAFlag_withRoot_returnsTrue() throws {
        let certificate = try NemIDX509Certificate(der: Data(base64Encoded: TestHelper.googleRoot, options: .ignoreUnknownCharacters)!)
        XCTAssertTrue(certificate.hasCAFlag())
    }
    
    func test_hasCAFlag_withLeaf_returnsFalse() throws {
        let certificate = try NemIDX509Certificate(der: Data(base64Encoded: TestHelper.googleLeaf, options: .ignoreUnknownCharacters)!)
        XCTAssertFalse(certificate.hasCAFlag())
    }
    
    func test_hasKeyUsage_digitalSignature_withRoot_returnsFalse() throws {
        let certificate = try NemIDX509Certificate(der: Data(base64Encoded: TestHelper.googleRoot, options: .ignoreUnknownCharacters)!)
        XCTAssertFalse(certificate.hasKeyUsage(.digitalSignature))
    }
    
    func test_hasKeyUsage_digitalSignature_withLeaf_returnsTrue() throws {
        let certificate = try NemIDX509Certificate(der: Data(base64Encoded: TestHelper.googleLeaf, options: .ignoreUnknownCharacters)!)
        XCTAssertTrue(certificate.hasKeyUsage(.digitalSignature))
    }
    
    func test_hasKeyUsage_keyCertSign_withRoot_returnsTrue() throws {
        let certificate = try NemIDX509Certificate(der: Data(base64Encoded: TestHelper.googleRoot, options: .ignoreUnknownCharacters)!)
        XCTAssertTrue(certificate.hasKeyUsage(.keyCertSign))
    }
    
    func test_hasKeyUsage_keyCertSign_withLeaf_returnFalse() throws {
        let certificate = try NemIDX509Certificate(der: Data(base64Encoded: TestHelper.googleLeaf, options: .ignoreUnknownCharacters)!)
        XCTAssertFalse(certificate.hasKeyUsage(.keyCertSign))
    }
    
    func test_commonName_withLeaf_returnsCorrectCommonName() throws {
        let certificate = try NemIDX509Certificate(der: Data(base64Encoded: TestHelper.googleLeaf, options: .ignoreUnknownCharacters)!)
        XCTAssertEqual(certificate.subjectCommonName, "*.google.com")
    }
    
    func test_hasExtendedKeyUsage_ocspSinging_withGoogleCert_returnsFalse() throws {
        let certificate = try NemIDX509Certificate(der: Data(base64Encoded: TestHelper.googleLeaf, options: .ignoreUnknownCharacters)!)
        XCTAssertEqual(certificate.hasExtendedKeyUsage(.ocspSigning), false)
    }
    
    func test_hasOCSPNoCheckExtension_withGoogleCert_returnsFalse() throws {
        let certificate = try NemIDX509Certificate(der: Data(base64Encoded: TestHelper.googleLeaf, options: .ignoreUnknownCharacters)!)
        XCTAssertEqual(certificate.hasOCSPNoCheckExtension(), false)
    }
    
    func test_hasExtendedKeyUsage_ocspSinging_withOCSPCertificate_returnsTrue() throws {
        XCTFail("Needs example cert.")
    }
}

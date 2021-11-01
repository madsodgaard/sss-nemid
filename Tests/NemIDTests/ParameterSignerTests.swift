import XCTest
@testable import NemID

final class ParameterSignerTests: XCTestCase {
    func test_sign_returnsSignedParameters() throws {
        let date = Date(timeIntervalSince1970: 1)
        
        let parameters = NemIDUnsignedClientParameters(
            clientFlow: .ocesLogin2,
            language: .danish,
            origin: URL(string: "https://nemid.dk")!,
            rememberUserID: nil,
            rememberUserIDInitialStatus: nil,
            timestamp: date,
            enableAwaitingAppApprovalEvent: true
        )
        
        let key = try NemIDRSAKey.private(pem: TestHelper.rsaPrivateKey)
        let certificate = try NemIDX509Certificate(der: Data(base64Encoded: TestHelper.googleLeaf, options: .ignoreUnknownCharacters)!)
        let configuration = NemIDConfiguration(spCertificate: certificate, privateKey: key, serviceProviderID: "", environment: .preproduction)
        let signer = NemIDParametersSigner(configuration: configuration)
        
        let signedParameters = try signer.sign(parameters)
        
        XCTAssertEqual(signedParameters.clientFlow, .ocesLogin2)
        XCTAssertEqual(signedParameters.language, .danish)
        XCTAssertEqual(signedParameters.origin?.absoluteString, "https://nemid.dk")
        XCTAssertEqual(signedParameters.rememberUserID, nil)
        XCTAssertEqual(signedParameters.rememberUserIDInitialStatus, nil)
        try XCTAssertEqual(signedParameters.spCert, certificate.toBase64EncodedDER())
        XCTAssertEqual(signedParameters.timestamp, date)
        XCTAssertEqual(signedParameters.paramsDigest, "DRTNpPkJnkYFEBBQGLqX20eg4/cOYEYZXtd55or/7VI=")
        XCTAssertEqual(signedParameters.digestSignature, "OXtgZLfEOauywJsjsm26v6W0DF/F3VXSnibgB1oSfk58K79HwldpQ/ryUHGiJKb/OmCovKc1P2Vrz6eCy1oMee0D7i6WLGvuARDfSfVO6TOhX2KqN7w3fUEoIMu1izETBArx//FN32AlqLOh1fcP0sF0ShzzoSYYGmEeTrlhMj4=")
        XCTAssertEqual(signedParameters.enableAwaitingAppApprovalEvent, true)
    }
}

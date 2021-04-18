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
        
        let key = try RSAKey.private(pem: rsaPrivateKey)
        let certificate = try X509Certificate(der: Data(base64Encoded: TestCertificates.googleLeaf, options: .ignoreUnknownCharacters)!)
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

let rsaPrivateKey = """
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDMEcwZYbKAGNYfpnGUB+mOSzU1n0VTX3Z0fdpBXscWyPn41FWK
TYXX6CBJ+BLVnLCXPnZF9d0ELfuPSXN7/a3nAmcTiHx9SUUQDlwVpHKmwimNt35j
YwbpAjWJ333XTW6yq+wvTNt8eydOHl5awLV/OlJEELfCBZgDqey/q968gwIDAQAB
AoGAM4Fmbx2ObPBX0uMylXctxqFKy77oQ3O7tQkytf8S5rhRBzGoaWDJoEXRKHo5
XrrOg03bkirM3sowTOjwAeJ0Kn9KiEkeMlAnIVTtVv+CLsxTMd4hP52qyvNbOpK+
rohJtn5pvuQ/mKwQOGzzzqsPzRYuOCPrTYmBP5Ac58yTB6ECQQD5aWr17AI9tTum
6O6wpaPicPTZFjhenFl7obXuBrALimH9LJ7iZnXQkq+iunvyks6aMHYncohj3py9
qEfOpQjTAkEA0XXDoZW0gTV0K0wHOjuClGledGe9Fmy/r9XmJOvnvdNPRbRK2SOO
1ebG+5kK4obKeM0QgVpf7I6vcO0qYWIvkQJANwHO+0n//IgaDefVrNP7Xxe2iKJj
8EnfWmsB6utCrGjqz6GlsR0T4tpXLjae25MRSeRiSrTx68TPIO0aWTMAzQJABw2/
M87V0FAbhGXADI76e8L8olDoBjxNTD+Yy3+CQ1s9XSyQJLXU1pE5/DkQK8a8RMsr
FiAUAORhNh1WgwcKcQJBALlOUOsgMzxOAmCGdKQuGCGw+vk7KhAX7GbWSDbAOCpc
wHcQvVwfd8D6Vw5XG8cek7PbISE/XRcxUyTGsxblKvA=
-----END RSA PRIVATE KEY-----
"""

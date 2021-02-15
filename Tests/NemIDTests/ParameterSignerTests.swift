import XCTest
import NemID

final class ParameterSignerTests: XCTestCase {
    func test_sign_returnsSignedParameters() throws {
        let date = Date(timeIntervalSince1970: 1)
        
        let parameters = NemIDUnsignedClientParameters(
            clientFlow: .ocesLogin2,
            language: .danish,
            origin: URL(string: "https://nemid.dk")!,
            rememberUserID: nil,
            rememberUserIDInitialStatus: nil,
            SPCert: "cert",
            timestamp: date)
        
        let rsaKey = try RSAKey.private(pem: rsaPrivateKey)
        let rsaSigner = RSASigner(privateKey: rsaKey)
        let signer = NemIDParametersSigner(rsaSigner: rsaSigner)
        
        let signedParameters = try signer.sign(parameters)
        
        XCTAssertEqual(signedParameters.clientFlow, .ocesLogin2)
        XCTAssertEqual(signedParameters.language, .danish)
        XCTAssertEqual(signedParameters.origin?.absoluteString, "https://nemid.dk")
        XCTAssertEqual(signedParameters.rememberUserID, nil)
        XCTAssertEqual(signedParameters.rememberUserIDInitialStatus, nil)
        XCTAssertEqual(signedParameters.SPCert, "cert")
        XCTAssertEqual(signedParameters.timestamp, date)
        XCTAssertEqual(signedParameters.paramsDigest, "5xhSpQNbt1pxNVASMrdg1irRp7uWR/JkZ5wT4c4IHd0=")
        XCTAssertEqual(signedParameters.digestSignature, "hUkuhANqk6oqa5+nHBZBc4/UpV0rj7iYn1d2UyBq4XxfyW6O2Qy+LcGN+ZGNVxDJklHbJjg8VbNyjaQ8kYzximmOAvUmCEL9WCw9eT50Uv+6H+uxSQYpe4NijBA2XKhkFAmYH6w2Mdnk9fdku9hq4geVSqCjqIU+8iK++b94LGw=")
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

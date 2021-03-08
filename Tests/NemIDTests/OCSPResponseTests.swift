import Foundation
@testable import NemID
import XCTest

final class OCSPResponseTests: XCTestCase {
    func test_init_withUnauthorizedResponse() throws {
        let response = try OCSPResponse(from: [UInt8](Data(base64Encoded: unauthorizedOcspResponse)!))
        XCTAssertEqual(response.responseStatus, .unauthorized)
        XCTAssertNil(response.basicOCSPResponse)
    }
    
    func test_init_withSuccesfullResponse() throws {
        let response = try OCSPResponse(from: [UInt8](Data(base64Encoded: successfullOcspResponse)!))
        XCTAssertEqual(response.responseStatus, .successful)
        let basicResponse = try XCTUnwrap(response.basicOCSPResponse)
        XCTAssertEqual(basicResponse.signatureAlgorithm, .sha256)
        let singleResponse = try XCTUnwrap(basicResponse.tbsResponseData.responses.first)
        // 2021-03-05 14:11:58Z
        XCTAssertEqual(singleResponse.thisUpdate, Date(timeIntervalSince1970: 1614866718))
        // 2021-03-12 13:11:57Z
        XCTAssertEqual(singleResponse.nextUpdate, Date(timeIntervalSince1970: 1615467917))
    }
    
    private let successfullOcspResponse = "MIIB1AoBAKCCAc0wggHJBgkrBgEFBQcwAQEEggG6MIIBtjCBn6IWBBSY0fhuEOvPm+xgnxiQG6DrfQn9KxgPMjAyMTAzMDQxNDA1MTlaMHQwcjBKMAkGBSsOAwIaBQAEFEJGMMInGdvecPCP/HPlpl9mOBe8BBSY0fhuEOvPm+xgnxiQG6DrfQn9KwIRAJqpJQj6G3+pBQAAAACHSiaAABgPMjAyMTAzMDQxNDA1MThaoBEYDzIwMjEwMzExMTMwNTE3WjANBgkqhkiG9w0BAQsFAAOCAQEAEpCZ5Dnd35gUM3JRIBRlk+FZ0kZsoMDbt9KBBN2YRd3dThnmHQptOiWv+SeQyX3hpffwxkfuf3vySqo8yMPfFTkEg7QMuWw72ZQ3wLujatl4+YIujijp/nQSCEBlHqG9YQSlm3RVX3xlq07qBDk2GgIOuVwbHsS9lXNOODm8pUMNoBkIdnywcVm3vFE7Pha8UCUdFs9yRjB5Rt0+uYY4gfjAgmFN9KR2cZHjjY+GLd4TSXBD9U9I+u0ekTkS25zbhz+2lJ/Nooj/T60BLTy1ruI+dsQ/S7o9ucpNd1RMU/cB3w36Ku9ZYiGGozYPkfC/GbQJvd0SbJpMw/jq2AYmtw=="
    
    private let unauthorizedOcspResponse = "MAMKAQY="
}

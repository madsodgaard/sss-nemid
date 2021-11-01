import XCTest
import XMLCoder
@testable import NemID

final class PIDCPRMatchResponseTests: XCTestCase {
    let xml = """
    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <method name="pidCprResponse" version="1.0">
        <response id="21DE82CA-EC47-4FB7-9129-E2741AC1F286">
            <status statusCode="1">
                <statusText language="DK">CPR svarer ikke til PID</statusText>
                <statusText language="UK">CPR does not match PID</statusText>
            </status>
            <pid>9208-2002-2-871296153613</pid>
            <cpr>0112160831</cpr>
            <redirURL>Not implemented</redirURL>
        </response>
    </method>
    """
    
    func test_decode() throws {
        let xmlDecoder = XMLDecoder()
        let decoded = try xmlDecoder.decode(PIDCPRMatchResponse.self, from: xml.data(using: .utf8)!)
        
        XCTAssertEqual(decoded.response.status.statusCode, 1)
        XCTAssertEqual(decoded.response.status.statusText.count, 2)
        XCTAssertEqual(decoded.response.status.statusText.first?.language, "DK")
        XCTAssertEqual(decoded.response.status.statusText.first?.value, "CPR svarer ikke til PID")
        XCTAssertEqual(decoded.response.status.statusText.last?.language, "UK")
        XCTAssertEqual(decoded.response.status.statusText.last?.value, "CPR does not match PID")
    }
}

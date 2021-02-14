import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(sss_nemidTests.allTests),
    ]
}
#endif

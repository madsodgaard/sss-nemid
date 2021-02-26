import Foundation
import XCTest
@testable import NemID

/*
 These test cases were taken from:
 https://www.w3.org/TR/xml-c14n2-testcases/
 */
final class C14NTests: XCTestCase {
    func test_c14n_testCase1() throws {
        let input = """
        <?xml version="1.0"?>

        <?xml-stylesheet   href="doc.xsl"
           type="text/xsl"   ?>

        <!DOCTYPE doc SYSTEM "doc.dtd">

        <doc>Hello, world!<!-- Comment 1 --></doc>

        <?pi-without-data     ?>

        <!-- Comment 2 -->

        <!-- Comment 3 -->
        """
        
        let c14n = try XCTUnwrap(input.data(using: .utf8)?.C14N())
        let output = String(bytes: c14n, encoding: .utf8)
        
        XCTAssertEqual(output, """
        <?xml-stylesheet href="doc.xsl"
           type="text/xsl"   ?>
        <doc>Hello, world!</doc>
        <?pi-without-data?>
        """)
    }
    
    func test_c14n_testCase2() throws {
        let input = """
        <doc>
           <clean>   </clean>
           <dirty>   A   B   </dirty>
           <mixed>
              A
              <clean>   </clean>
              B
              <dirty>   A   B   </dirty>
              C
           </mixed>
        </doc>
        """
        
        let c14n = try XCTUnwrap(input.data(using: .utf8)?.C14N())
        let output = String(bytes: c14n, encoding: .utf8)
        
        XCTAssertEqual(output, """
        <doc>
           <clean>   </clean>
           <dirty>   A   B   </dirty>
           <mixed>
              A
              <clean>   </clean>
              B
              <dirty>   A   B   </dirty>
              C
           </mixed>
        </doc>
        """)
    }
}

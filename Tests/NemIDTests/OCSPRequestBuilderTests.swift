import Foundation
import XCTest
@testable import NemID
@_implementationOnly import CNemIDSSL

final class OCSPRequestBuilderTests: XCTestCase {
    func test_OCSP() throws {
        let certificate = try X509Certificate(der: Data(base64Encoded: TestCertificates.googleLeaf, options: .ignoreUnknownCharacters)!)
        let issuer = try X509Certificate(der: Data(base64Encoded: TestCertificates.googleIntermediate, options: .ignoreUnknownCharacters)!)
        let req = OCSPRequestBuilder.build(certificate: certificate, issuer: issuer)
//        guard let serialNumberASN1String = CNemIDBoringSSL_ASN1_OCTET_STRING_new() else {
//            XCTFail()
//            return
//        }
//        let string = [UInt8]("my-string".utf8)
//        CNemIDBoringSSL_ASN1_OCTET_STRING_set(serialNumberASN1String, string, -1)
//
//        guard let certid = OCSP_CERTID_new() else {
//            XCTFail()
//            return
//        }
//        print(certid.pointee)
////        certid.pointee.issuerKeyHash = serialNumberASN1String.pointee
//        CNemIDBoringSSL_ASN1_STRING_copy(&certid.pointee.issuerKeyHash, serialNumberASN1String)
//        print(certid.pointee)

//        withUnsafeMutablePointer(to: &certid!.pointee.issuerNameHash) { ptr in
//            ptr.assign(from: serialNumberASN1String!, count: 1)
//        }
        
//        var out: UnsafeMutablePointer<UInt8>?
//        let length = i2d_OCSP_CERTID(certid, &out)
//
//        guard let namePointer = out else { return }
//        let asn1Bytes = [UInt8](UnsafeBufferPointer(start: namePointer, count: Int(length)))
//        CNemIDBoringSSL_OPENSSL_free(namePointer)
//        print(Data(asn1Bytes).base64EncodedString())
    }
}

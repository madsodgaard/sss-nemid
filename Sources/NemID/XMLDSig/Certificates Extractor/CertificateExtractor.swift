import Foundation

protocol CertificateExtrator {
    func extract(from xml: ParsedXMLDSigResponse) throws -> CertificateChain
}

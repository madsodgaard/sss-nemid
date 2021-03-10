import Foundation

protocol XMLDSigParser {
    func parse(_ xml: [UInt8]) throws -> ParsedXMLDSigResponse
}

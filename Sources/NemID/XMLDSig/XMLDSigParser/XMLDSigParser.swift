import Foundation

protocol XMLDSigParser {
    func parse(_ xml: String) throws -> ParsedXMLDSigResponse
}

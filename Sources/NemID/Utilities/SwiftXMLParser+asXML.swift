import Foundation
import SwiftyXMLParser

// https://github.com/yahoojapan/SwiftyXMLParser/blob/ec7f183642adf429babd867d1a38c5c6912408ba/SwiftyXMLParser/Accessor.swift#L453
extension SwiftyXMLParser.XML.Accessor {
    public func asXML() throws -> String {
        if case .failure(let err) = self {
            throw err
        }
        
        var doc: String = ""
        for hit in self {
            switch hit {
            case .singleElement(let element):
                doc += traverse(element)
            case .sequence(let elements):
                doc += elements.reduce("") { (sum, el) in sum + traverse(el) }
            case .failure(let error):
                throw error
            }
        }
        
        return doc
    }
    
    private func traverse(_ element: XML.Element) -> String {
        let name = element.name
        let text = element.text ?? ""
        let attrs = element.attributes.map { (k, v) in "\(k)=\"\(v)\""  }.joined(separator: " ")
        
        let childDocs = element.childElements.reduce("", { (result, element) in
            result + traverse(element)
        })
        
        if name == "XML.Parser.AbstructedDocumentRoot" {
            return childDocs
        } else {
            return "<\(name) \(attrs)>\(text)\(childDocs)</\(name)>"
        }
    }
}

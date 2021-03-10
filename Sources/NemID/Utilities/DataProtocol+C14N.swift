import Foundation
import Clibxml2

extension DataProtocol {
    /// Returns this XML data as C14N data
    func C14N() -> [UInt8]? {
        precondition(self.regions.count <= 1, "There is no such thing as data that has discontiguous regions")
        guard let region = self.regions.first else { return nil }
        
        guard let xmlDoc = region.withUnsafeBytes({ bytes -> xmlDocPtr? in
            let buf = bytes.bindMemory(to: Int8.self)
            return xmlReadMemory(buf.baseAddress, numericCast(buf.count), "noname.xml", nil, 0)
        }) else { return nil }
        defer { xmlFreeDoc(xmlDoc) }
        
        var outBytes: UnsafeMutablePointer<UInt8>?
        let outLen = xmlC14NDocDumpMemory(xmlDoc, nil, numericCast(XML_C14N_1_1.rawValue), nil, 0, &outBytes)
        guard outBytes != nil, outLen > 0 else { return nil }
        defer { xmlFree(outBytes) }
        
        return .init(UnsafeBufferPointer(start: outBytes, count: numericCast(outLen)))
    }
}

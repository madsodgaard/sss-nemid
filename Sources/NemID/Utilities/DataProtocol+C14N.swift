import Foundation
import libxml2

extension DataProtocol {
    /// Returns this XML data as C14N data
    func C14N() -> [UInt8]? {
        self.copyBytes()
            .withUnsafeBufferPointer { ptr in
                ptr.withMemoryRebound(to: Int8.self) { int8Ptr in
                    guard let xmlDoc = xmlReadMemory(int8Ptr.baseAddress, CInt(ptr.count), "noname.xml", nil, 0)
                    else { return nil }
                    defer { xmlFreeDoc(xmlDoc) }
                    
                    var outputBytes: UnsafeMutablePointer<UInt8>?
                    let outputLength = xmlC14NDocDumpMemory(xmlDoc, nil, numericCast(XML_C14N_1_0.rawValue), nil, 0, &outputBytes)
                    guard let outputStartPointer = outputBytes else { return nil }
                    
                    let c14n = [UInt8](UnsafeBufferPointer(start: outputStartPointer, count: Int(outputLength)))
                    xmlFree(outputStartPointer)
                    return c14n
                }
            }
    }
}

import Foundation
import Clibxml2

struct libxml2XMLDSigParser: XMLDSigParser {
    enum ParserError: Error {
        case failedToAllocateXMLDoc
        case failedToCreateXPathContext
        case failedToRegisterNamespace
        case failedToParseCertificates
        case failedToParseSignedElement
        case failedToParseDigestValue
        case failedToParseSignatureValue
        case failedToParseSignedInfo
    }
    
    func parse(_ xml: [UInt8]) throws -> ParsedXMLDSigResponse {
        guard let xmlDoc = xml.withUnsafeBytes({ bytes -> xmlDocPtr? in
            let buf = bytes.bindMemory(to: Int8.self)
            return xmlReadMemory(buf.baseAddress, numericCast(buf.count), "noname.xml", nil, 0)
        }) else {
            throw ParserError.failedToAllocateXMLDoc
        }
        defer { xmlFreeDoc(xmlDoc) }
        
        guard let context = xmlXPathNewContext(xmlDoc) else {
            throw ParserError.failedToCreateXPathContext
        }
        defer { xmlXPathFreeContext(context) }
        
        guard xmlXPathRegisterNs(context, "openoces", "http://www.openoces.org/2006/07/signature") == 0 else {
            throw ParserError.failedToRegisterNamespace
        }
        guard xmlXPathRegisterNs(context, "ds", "http://www.w3.org/2000/09/xmldsig") == 0 else {
            throw ParserError.failedToRegisterNamespace
        }
        
        // Parse signed element
        guard let signedElementData = parseFirstXPathElementAsXML(
                query: #"/openoces:signature/ds:Signature/ds:Object[@Id="ToBeSigned"]"#,
                context: context,
                in: xmlDoc
        ) else {
            throw ParserError.failedToParseSignedElement
        }
        
        // Parse singedInfo
        guard let signedInfoData = parseFirstXPathElementAsXML(
                query: "/openoces:signature/ds:Signature/ds:SignedInfo",
                context: context,
                in: xmlDoc
        ) else {
            throw ParserError.failedToParseSignedInfo
        }
        
        // Parse digestValue
        guard let digestValue = parseXPathValue(
                query: "/openoces:signature/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue",
                context: context
        ) else {
            throw ParserError.failedToParseDigestValue
        }
        
        // Parse signatureValue
        guard let signatureValue = parseXPathValue(query: "/openoces:signature/ds:Signature/ds:SignatureValue", context: context) else {
            throw ParserError.failedToParseSignatureValue
        }
        
        // Parse certificates
        guard let certsXMLObject = xmlXPathEvalExpression("/openoces:signature/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate", context) else {
            throw ParserError.failedToParseCertificates
        }
        defer { xmlXPathFreeObject(certsXMLObject) }
        guard let nodeSetPtr = certsXMLObject.pointee.nodesetval else {
            throw ParserError.failedToParseCertificates
        }
        
        let certificates = try (0..<nodeSetPtr.pointee.nodeNr).map { index -> String in
            guard let nodePtr = nodeSetPtr.pointee.nodeTab[numericCast(index)],
                  let content = xmlNodeGetContent(nodePtr)
            else {
                throw ParserError.failedToParseCertificates
            }
            defer { xmlFree(content) }
            return String(cString: content)
        }
        
        return ParsedXMLDSigResponse(
            signatureValue: signatureValue,
            signedInfo: signedInfoData,
            referenceDigestValue: digestValue,
            objectToBeSigned: signedElementData,
            x509Certificates: certificates
        )
    }
    
    /// Parses a XPath query and returns the first element as XML data.
    private func parseFirstXPathElementAsXML(query: String, context: xmlXPathContextPtr, in xmlDoc: xmlDocPtr) -> Data? {
        guard let xPathObject = xmlXPathEvalExpression(query, context) else {
            return nil
        }
        guard let nodePtr = xPathObject.pointee.nodesetval?.pointee.nodeTab[0] else { return nil }
        guard let xmlBuffer = xmlBufferCreate() else { return nil }
        defer { xmlBufferFree(xmlBuffer) }
        guard let xmlOutputBuffer = xmlOutputBufferCreateBuffer(xmlBuffer, nil) else { return nil }
        defer { xmlOutputBufferClose(xmlOutputBuffer) }
        xmlNodeDumpOutput(xmlOutputBuffer, xmlDoc, nodePtr, 0, 1, nil)
        guard let dataPtr = xmlOutputBufferGetContent(xmlOutputBuffer) else { return nil }
        let length = xmlOutputBufferGetSize(xmlOutputBuffer)
        guard length > 0 else { return nil }
        return Data(bytes: dataPtr, count: length)
    }
    
    /// This function parses a single value from a element by the xpath `query`
    ///
    /// For example, this function returns "string" from this element: `<element>string</element>`
    private func parseXPathValue(query: String, context: xmlXPathContextPtr) -> String? {
        guard let xmlObject = xmlXPathEvalExpression(query, context) else { return nil }
        defer { xmlXPathFreeObject(xmlObject) }
        guard let nodeSetPtr = xmlObject.pointee.nodesetval else { return nil }
        // We only expect one value
        guard nodeSetPtr.pointee.nodeNr == 1 else { return nil }
        guard let nodePtr = nodeSetPtr.pointee.nodeTab[0],
              let content = xmlNodeGetContent(nodePtr)
        else { return nil }
        defer { xmlFree(content) }
        return String(cString: content)
    }
}

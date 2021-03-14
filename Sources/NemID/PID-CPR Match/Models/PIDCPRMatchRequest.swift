import Foundation
import XMLCoder

struct PIDCPRMatchRequest: Encodable {
    struct Method: Encodable, DynamicNodeEncoding {
        struct Request: Encodable, DynamicNodeEncoding {
            let id: String
            let serviceProviderID: String
            let pid: String
            let cpr: String
            
            enum CodingKeys: String, CodingKey {
                case id
                case serviceProviderID = "serviceId"
                case pid
                case cpr
            }
            
            static func nodeEncoding(for key: CodingKey) -> XMLEncoder.NodeEncoding {
                switch key {
                case CodingKeys.id: return .attribute
                default: return .element
                }
            }
        }
        
        let name: String = "pidCprRequest"
        let version: String = "1.0"
        let request: Request
        
        enum CodingKeys: String, CodingKey {
            case name
            case version
            case request
        }
        
        static func nodeEncoding(for key: CodingKey) -> XMLEncoder.NodeEncoding {
            switch key {
            case CodingKeys.name: return .attribute
            case CodingKeys.version: return .attribute
            default: return .element
            }
        }
    }
    
    let method: Method
}

import Foundation
import XMLCoder

/// Decodes as <method>
struct PIDCPRMatchResponse: Decodable {
    struct Response: Decodable {
        struct Status: Decodable, DynamicNodeDecoding {
            struct StatusText: Decodable, DynamicNodeDecoding {
                let language: String
                let value: String
                
                enum CodingKeys: String, CodingKey {
                    case language
                }
                
                static func nodeDecoding(for key: CodingKey) -> XMLDecoder.NodeDecoding {
                    switch key {
                    case CodingKeys.language:
                        return .attribute
                    default:
                        return .element
                    }
                }
                
                init(from decoder: Decoder) throws {
                    let container = try decoder.container(keyedBy: CodingKeys.self)
                    let valueContainer = try decoder.singleValueContainer()
                    
                    self.language = try container.decode(String.self, forKey: .language)
                    self.value = try valueContainer.decode(String.self)
                }
            }
            
            let statusCode: Int
            let statusText: [StatusText]
            
            enum CodingKeys: String, CodingKey {
                case statusCode
                case statusText
            }
            
            static func nodeDecoding(for key: CodingKey) -> XMLDecoder.NodeDecoding {
                switch key {
                case CodingKeys.statusCode:
                    return .attribute
                default:
                    return .element
                }
            }
        }
        
        let status: Status
    }
    
    let response: Response
}

import Foundation

struct PIDCPRServiceError: LocalizedError, CustomStringConvertible {
    let statusCode: Int
    let reason: String?
    
    var description: String {
        var desc = "PIDCPRServiceError(status: \(statusCode)"
        if let reason = reason {
            desc += ", message: \(reason))"
        } else {
            desc += ")"
        }
        return desc
    }
    
    var errorDescription: String? {
        description
    }
}

import Foundation

extension Bool {
    var nemIDRepresentation: String {
        switch self {
        case true: return "TRUE"
        case false: return "FALSE"
        }
    }
}

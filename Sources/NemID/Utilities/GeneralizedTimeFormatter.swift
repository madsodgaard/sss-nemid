import Foundation

enum GeneralizedTimeFormatter {
    static private let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = .init(identifier: "en-US")
        formatter.dateFormat = "yyyyMMddHHmmssZ"
        return formatter
    }()
    
    static func toDate(_ generalizedTime: String) -> Date? {
        Self.dateFormatter.date(from: generalizedTime)
    }
}

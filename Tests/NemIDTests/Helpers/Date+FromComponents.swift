import Foundation

extension Date {
    init(year: Int, month: Int, day: Int, hour: Int, minute: Int, second: Int) {
        var date = DateComponents()
        date.calendar = Calendar(identifier: .gregorian)
        date.year = year
        date.month = month
        date.day = day
        date.hour = hour
        date.minute = minute
        date.second = second
        date.timeZone = TimeZone(abbreviation: "UTC")
        self = date.date!
    }
}

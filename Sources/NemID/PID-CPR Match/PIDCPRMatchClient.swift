import Foundation
import NIO

public protocol PIDCPRMatchClient {
    /// Verifies that a given User PID`pid` matches a danish CPR number `cpr`.
    func verifyPID(_ pid: String, matches cpr: String) -> EventLoopFuture<Void>
}

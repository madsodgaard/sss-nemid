import NIO
import Logging

public protocol NemIDPIDCPRMatchClient {
    /// Verifies that a given User PID`pid` matches a danish CPR number `cpr`.
    func verifyPID(_ pid: String, matches cpr: String) -> EventLoopFuture<Bool>
    
    func delegating(to eventLoop: EventLoop) -> Self
    func logging(to logger: Logger) -> Self
}

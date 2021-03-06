import Foundation
import NIO

protocol OCSPClient {
    func send(request: OCSPRequest) -> EventLoopFuture<OCSPResponse>
}


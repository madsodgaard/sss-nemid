import Foundation
import NIOCore

protocol OCSPClient {
    func send(request: OCSPRequest) -> EventLoopFuture<OCSPResponse>
}


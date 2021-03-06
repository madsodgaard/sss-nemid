import Foundation
import NIO
import AsyncHTTPClient
import Logging

struct HTTPOCSPClient: OCSPClient {
    enum HTTPOCSPClientError: Error {
        case invalidContentTypeHeader
        case responseBodyWasEmpty
    }
    
    private let client: HTTPClient
    private let eventLoop: EventLoop
    private let logger: Logger
    
    init(client: HTTPClient, eventLoop: EventLoop, logger: Logger) {
        self.client = client
        self.eventLoop = eventLoop
        self.logger = logger
    }
    
    func send(request: OCSPRequest) -> EventLoopFuture<OCSPResponse> {
        do {
            logger.debug("Sending OCSP request...")
            var httpRequest = try HTTPClient.Request(url: request.endpoint, method: .POST)
            httpRequest.body = .byteBuffer(.init(bytes: request.requestDER))
            httpRequest.headers.add(name: "Content-Type", value: "application/ocsp-request")
            return client.execute(
                request: httpRequest,
                eventLoop: .delegate(on: eventLoop),
                logger: self.logger
            )
            .flatMapThrowing { response in
                logger.debug("Received response from OCSP server")
                guard response.headers.first(name: "Content-Type") == "application/ocsp-response" else {
                    throw HTTPOCSPClientError.invalidContentTypeHeader
                }
                
                guard let body = response.body else { throw HTTPOCSPClientError.responseBodyWasEmpty }
                #warning("memory copy")
                return try OCSPResponse(from: [UInt8](body.readableBytesView))
            }
        } catch {
            return eventLoop.makeFailedFuture(error)
        }
    }
}

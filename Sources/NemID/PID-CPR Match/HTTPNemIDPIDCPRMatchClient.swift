import Foundation
import NIO
import AsyncHTTPClient
import XMLCoder
import Logging

struct HTTPNemIDPIDCPRMatchClient: NemIDPIDCPRMatchClient {
    enum HTTPPIDCPRMatchClientError: Error {
        case failedToBuildRequest
    }
    
    private let configuration: NemIDConfiguration
    private let eventLoop: EventLoop
    private let xmlEncoder = XMLEncoder()
    private let httpClient: HTTPClient
    private let logger: Logger
    
    init(
        configuration: NemIDConfiguration,
        eventLoop: EventLoop,
        httpClient: HTTPClient,
        logger: Logger
    ) {
        self.configuration = configuration
        self.eventLoop = eventLoop
        self.httpClient = httpClient
        self.logger = logger
    }
    
    func verifyPID(_ pid: String, matches cpr: String) -> EventLoopFuture<Void> {
        do {
            let request = PIDCPRMatchRequest(
                method: .init(
                    request: .init(
                        id: UUID().uuidString,
                        serviceProviderID: configuration.serviceProviderID,
                        pid: pid,
                        cpr: cpr
                    )
                )
            )
            
            let requestData = try xmlEncoder.encode(request, withRootKey: "method", header: .init(version: 1.0, encoding: "iso-8859-1"))
            guard let requestString = String(data: requestData, encoding: .utf8) else {
                throw HTTPPIDCPRMatchClientError.failedToBuildRequest
            }
            let formEncodedRequest = try "PID_REQUEST=\(requestString)".urlEncoded()
            
            var httpRequest = try HTTPClient.Request(url: configuration.environment.pidCPRMatchEndpoint, method: .POST)
            httpRequest.headers.add(name: "Content-Type", value: "application/x-www-form-urlencoded")
            httpRequest.body = .string(formEncodedRequest)
            
            #warning("need to add certificate to request")
            fatalError()
//            return httpClient.execute(request: httpRequest, eventLoop: .delegate(on: eventLoop), logger: logger)
        } catch {
            return eventLoop.makeFailedFuture(error)
        }
    }
}

import Foundation
import NIOCore
import NIOFoundationCompat
import AsyncHTTPClient
import XMLCoder
import Logging
import NIOSSL

enum HTTPPIDCPRMatchClientError: Error {
    case failedToBuildRequest
    case badStatusCode
    case invalidResponseBody
}

public struct HTTPNemIDPIDCPRMatchClient: NemIDPIDCPRMatchClient {
    private let configuration: NemIDConfiguration
    private let eventLoop: EventLoop
    private let xmlEncoder = XMLEncoder()
    private let xmlDecoder = XMLDecoder()
    private let httpClient: HTTPClient
    private let logger: Logger
    
    public init(
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
    
    public func verifyPID(_ pid: String, matches cpr: String) -> EventLoopFuture<Bool> {
        do {
            let request = PIDCPRMatchRequest(
                request: .init(
                    id: UUID().uuidString,
                    serviceProviderID: configuration.serviceProviderID,
                    pid: pid,
                    cpr: cpr
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
            
            // Configure TLS
            let certificate = try NIOSSLCertificate(bytes: configuration.spCertificate.toDERBytes(), format: .der)
            let privateKey = try NIOSSLPrivateKey(bytes: configuration.privateKey.toDERBytes(), format: .der)
            var tlsConfiguration = TLSConfiguration.makeClientConfiguration()
            tlsConfiguration.certificateChain = [.certificate(certificate)]
            tlsConfiguration.privateKey = .privateKey(privateKey)
            httpRequest.tlsConfiguration = tlsConfiguration
            
            return httpClient
                .execute(request: httpRequest, eventLoop: .delegate(on: eventLoop), logger: logger)
                .flatMapThrowing { response -> PIDCPRMatchResponse in
                    guard (200...299).contains(response.status.code) else {
                        throw HTTPPIDCPRMatchClientError.badStatusCode
                    }
                    guard let body = response.body else {
                        throw HTTPPIDCPRMatchClientError.invalidResponseBody
                    }
                    return try xmlDecoder.decode(PIDCPRMatchResponse.self, from: Data(buffer: body))
                }
                .flatMapThrowing { decodedResponse in
                    switch decodedResponse.response.status.statusCode {
                    case 0:
                        return true
                    case 1:
                        return false
                    default:
                        let reason = decodedResponse.response.status.statusText
                                .first(where: { $0.language == "UK" })?
                                .value
                        throw PIDCPRServiceError(
                            statusCode: decodedResponse.response.status.statusCode,
                            reason: reason
                        )
                    }
                }
        } catch {
            return eventLoop.makeFailedFuture(error)
        }
    }
    
    public func delegating(to eventLoop: EventLoop) -> HTTPNemIDPIDCPRMatchClient {
        HTTPNemIDPIDCPRMatchClient(
            configuration: self.configuration,
            eventLoop: eventLoop,
            httpClient: self.httpClient,
            logger: self.logger
        )
    }
    
    public func logging(to logger: Logger) -> HTTPNemIDPIDCPRMatchClient {
        HTTPNemIDPIDCPRMatchClient(
            configuration: self.configuration,
            eventLoop: self.eventLoop,
            httpClient: self.httpClient,
            logger: logger
        )
    }
}

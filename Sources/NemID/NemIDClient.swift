import Foundation
import NIO
import Logging
import AsyncHTTPClient

public protocol NemIDClient {
    func delegating(to eventLoop: EventLoop) -> Self
}

public struct LiveNemIDClient: NemIDClient {
    private let httpClient: HTTPClient
    private let logger: Logger
    private let eventLoop: EventLoop
    private let configuration: NemIDConfiguration
    private let responseHandler: NemIDResponseHandler
    private let parametersSigner: NemIDParametersSigner
    
    public init(eventLoop: EventLoop, httpClient: HTTPClient, logger: Logger, configuration: NemIDConfiguration) {
        self.eventLoop = eventLoop
        self.httpClient = httpClient
        self.logger = logger
        self.configuration = configuration
        responseHandler = NemIDResponseHandler(
            xmlParser: libxml2XMLDSigParser(),
            certificateExtractor: DefaultCertificateExtractor(),
            ocspClient: HTTPOCSPClient(client: httpClient, eventLoop: eventLoop, logger: logger),
            eventLoop: eventLoop
        )
        parametersSigner = NemIDParametersSigner(
            rsaSigner: RSASigner(key: try! .private(pem: "")),
            configuration: configuration
        )
    }
    
    public func delegating(to eventLoop: EventLoop) -> LiveNemIDClient {
        LiveNemIDClient(eventLoop: eventLoop, httpClient: self.httpClient, logger: self.logger, configuration: self.configuration)
    }
}

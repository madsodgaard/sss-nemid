import Foundation
import NIO
import Logging
import AsyncHTTPClient

public protocol NemIDLoginService {
    /// Signs the supplied parameters and returns the parameters as signed, ready to be sent to the client.
    func signParameters(_ parameters: NemIDUnsignedClientParameters) -> EventLoopFuture<NemIDSignedClientParameters>
    
    /// Validates a XMLDSig message from client, according to the NemID documentation, and returns the certificate user.
    /// - Parameters:
    ///     - response: The XMLDSig xml-document as UTF-8 encoded bytes
    func validateAndExtractUser(fromResponse response: [UInt8]) -> EventLoopFuture<NemIDUser>
    
    func delegating(to eventLoop: EventLoop) -> Self
    func logging(to logger: Logger) -> Self
}

public struct LiveNemIDLoginService: NemIDLoginService {
    private let httpClient: HTTPClient
    private let logger: Logger
    private let eventLoop: EventLoop
    private let configuration: NemIDConfiguration
    
    public init(eventLoop: EventLoop, httpClient: HTTPClient, logger: Logger, configuration: NemIDConfiguration) {
        self.eventLoop = eventLoop
        self.httpClient = httpClient
        self.logger = logger
        self.configuration = configuration
    }
    
    public func validateAndExtractUser(fromResponse response: [UInt8]) -> EventLoopFuture<NemIDUser> {
        let responseHandler = NemIDResponseHandler(
            xmlParser: libxml2XMLDSigParser(),
            certificateExtractor: DefaultCertificateExtractor(),
            ocspClient: HTTPOCSPClient(client: httpClient, eventLoop: eventLoop, logger: logger),
            eventLoop: self.eventLoop
        )
        
        return responseHandler.verifyAndExtractUser(fromXML: response)
    }
    
    public func signParameters(_ parameters: NemIDUnsignedClientParameters) -> EventLoopFuture<NemIDSignedClientParameters> {
        do {
            let parametersSigner = NemIDParametersSigner(
                rsaSigner: RSASigner(key: try! .private(pem: "")),
                configuration: self.configuration
            )
            
            return eventLoop.makeSucceededFuture(try parametersSigner.sign(parameters))
        } catch {
            return eventLoop.makeFailedFuture(error)
        }
    }
    
    public func delegating(to eventLoop: EventLoop) -> LiveNemIDLoginService {
        LiveNemIDLoginService(eventLoop: eventLoop, httpClient: self.httpClient, logger: self.logger, configuration: self.configuration)
    }
    
    public func logging(to logger: Logger) -> LiveNemIDLoginService {
        LiveNemIDLoginService(eventLoop: self.eventLoop, httpClient: self.httpClient, logger: logger, configuration: self.configuration)
    }
}

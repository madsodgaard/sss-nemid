import Foundation

protocol NemIDResponseHandler {
    /// Verifies a response from a NemID client flow such as logging in and extratcs the user as `NemIDUser`
    ///
    /// Does the checks in respect to the NemID documentation p. 34:
    /// - Extract the certficiates from XMLDSig
    /// - Validate the signature on XMLDSig
    /// - Validate the certificate and identify CA as OCES throughout the chain
    /// - Check that the certificate has not expired
    /// - Check that the certficate has not been revoked
    ///
    /// - Parameters:
    ///     - response: The XML as a `String` received from the client.
    /// - Returns: A `NemIDUser` as the verified certificate user.
    func verifyAndExtractUser(from response: String) throws -> NemIDUser
}

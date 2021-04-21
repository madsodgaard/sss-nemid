import Foundation

enum NemIDUserError: Error {
    case failedToExtractCommonName
    case failedToExtractSerialNumber
}

/// A model that represents a private NemID user (POCES certificate) with their PID and their name.
public struct NemIDUser {
    /// The PID representing this user. This value can be used to verify a given CPR matches with this user.
    public let pid: String
    
    /// The name of the user. For example "Bob Hansen"
    /// - Important:
    /// If the user has chosen not to share their name, this value is `nil`.
    public let name: String?
    
    init(from certificate: NemIDX509Certificate) throws {
        guard let commonName = certificate.subjectCommonName else {
            throw NemIDUserError.failedToExtractCommonName
        }
        guard let pid = certificate.subjectSerialNumber?.components(separatedBy: "PID:").last else {
            throw NemIDUserError.failedToExtractSerialNumber
        }
        self.init(pid: pid, name: commonName != "Pseudonym" ? commonName : nil)
    }
    
    private init(pid: String, name: String?) {
        self.pid = pid
        self.name = name
    }
}

extension NemIDUser: CustomStringConvertible {
    public var description: String {
        "NemIDUser(name: \(String(describing: self.name)), PID: \(self.pid))"
    }
}

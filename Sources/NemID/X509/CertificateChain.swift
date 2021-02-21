import Foundation

struct CertificateChain {
    let root: X509Certificate
    let intermediate: X509Certificate
    let leaf: X509Certificate
}

// MARK: Sequence
extension CertificateChain: Sequence {
    func makeIterator() -> CertificateChainIterator {
        CertificateChainIterator(certificates: [self.root, self.intermediate, self.leaf])
    }
}

// MARK: - CertificateChainIterator
struct CertificateChainIterator: IteratorProtocol {
    let certificates: [X509Certificate]
    private var currentPos = 0
    
    init(certificates: [X509Certificate]) {
        self.certificates = certificates
    }
    
    mutating func next() -> X509Certificate? {
        if currentPos < certificates.count {
            let oldPosition = currentPos
            currentPos += 1
            return certificates[oldPosition]
        }
        return nil
    }
}

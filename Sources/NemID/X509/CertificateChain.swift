import Foundation

struct CertificateChain {
    let root: NemIDX509Certificate
    let intermediate: NemIDX509Certificate
    let leaf: NemIDX509Certificate
}

// MARK: Sequence
extension CertificateChain: Sequence {
    func makeIterator() -> CertificateChainIterator {
        CertificateChainIterator(certificates: [self.root, self.intermediate, self.leaf])
    }
}

// MARK: - CertificateChainIterator
struct CertificateChainIterator: IteratorProtocol {
    let certificates: [NemIDX509Certificate]
    private var currentPos = 0
    
    init(certificates: [NemIDX509Certificate]) {
        self.certificates = certificates
    }
    
    mutating func next() -> NemIDX509Certificate? {
        if currentPos < certificates.count {
            let oldPosition = currentPos
            currentPos += 1
            return certificates[oldPosition]
        }
        return nil
    }
}

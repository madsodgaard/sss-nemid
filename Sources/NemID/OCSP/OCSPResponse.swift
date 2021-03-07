import Foundation
@_implementationOnly import CNemIDBoringSSL

enum OCSPResponseError: Error {
    case failedToParseResponse
    case unknownResponseStatus(UInt8)
    case responseTypeWasNotOCSPBasic
    case unknownSignatureAlgorithm(Int32)
    case unknownHashAlgorithm(Int32)
    case nextUpdateDateWasNotPresent
    case unknownCertStatus(UInt32)
}

struct OCSPResponse {
    let responseStatus: OCSPResponseStatus
    let basicOCSPResponse: BasicOCSPResponse?
    
    init(from derBytes: [UInt8]) throws {
        var cbs = CBS()
        CNemIDBoringSSL_CBS_init(&cbs, derBytes, derBytes.count)
        
        var ocspResponseCBS = CBS()
        guard CNemIDBoringSSL_CBS_get_asn1(&cbs, &ocspResponseCBS, CBS_ASN1_SEQUENCE) == 1 else {
            throw OCSPResponseError.failedToParseResponse
        }
        
        var responseStatusCBS = CBS()
        guard CNemIDBoringSSL_CBS_get_asn1(&ocspResponseCBS, &responseStatusCBS, CBS_ASN1_ENUMERATED) == 1 else {
            throw OCSPResponseError.failedToParseResponse
        }
        
        // Parse response status
        var responseStatusValue: UInt8 = 0
        guard CNemIDBoringSSL_CBS_get_u8(&responseStatusCBS, &responseStatusValue) == 1 else {
            throw OCSPResponseError.failedToParseResponse
        }
        
        guard let responseStatus = OCSPResponseStatus(asn1Value: responseStatusValue) else {
            throw OCSPResponseError.unknownResponseStatus(responseStatusValue)
        }
        self.responseStatus = responseStatus
        
        // Parse response bytes
        var responseBytesCBS = CBS()
        var isResponseBytesPresent: Int32 = 0
        guard CNemIDBoringSSL_CBS_get_optional_asn1(
            &ocspResponseCBS,
            &responseBytesCBS,
            &isResponseBytesPresent,
            CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 0
        ) == 1 else {
            throw OCSPResponseError.failedToParseResponse
        }
        guard isResponseBytesPresent == 1 else {
            self.basicOCSPResponse = nil
            return
        }
        
        // Parse contents of responseBytes
        var responseBytesChildCBS = CBS()
        guard CNemIDBoringSSL_CBS_get_asn1(&responseBytesCBS, &responseBytesChildCBS, CBS_ASN1_SEQUENCE) == 1 else {
            throw OCSPResponseError.failedToParseResponse
        }
        
        // Parse responseType
        var responseTypeCBS = CBS()
        guard CNemIDBoringSSL_CBS_get_asn1(&responseBytesChildCBS, &responseTypeCBS, CBS_ASN1_OBJECT) == 1 else {
            throw OCSPResponseError.failedToParseResponse
        }
        let responseTypeNID = CNemIDBoringSSL_OBJ_cbs2nid(&responseTypeCBS)
        guard responseTypeNID == NID_id_pkix_OCSP_basic else { throw OCSPResponseError.responseTypeWasNotOCSPBasic }
        
        // Parse response
        var responseCBS = CBS()
        guard CNemIDBoringSSL_CBS_get_asn1(&responseBytesChildCBS, &responseCBS, CBS_ASN1_OCTETSTRING) == 1 else {
            throw OCSPResponseError.failedToParseResponse
        }
        
        // Parse BasicOCSPResponse
        var basicOCSPResponseCBS = CBS()
        guard CNemIDBoringSSL_CBS_get_asn1(&responseCBS, &basicOCSPResponseCBS, CBS_ASN1_SEQUENCE) == 1 else {
            throw OCSPResponseError.failedToParseResponse
        }
        
        self.basicOCSPResponse = try BasicOCSPResponse(cbs: &basicOCSPResponseCBS)
    }
}

// MARK: OCSPResponseStatus
extension OCSPResponse {
    enum OCSPResponseStatus {
        case successful
        case malformedRequest
        case internalError
        case tryLater
        case sigRequired
        case unauthorized
        
        init?(asn1Value: UInt8) {
            switch asn1Value {
            case 0: self = .successful
            case 1: self = .malformedRequest
            case 2: self = .internalError
            case 3: self = .tryLater
            case 5: self = .sigRequired
            case 6: self = .unauthorized
            default: return nil
            }
        }
    }
}

// MARK: BasicOCSPResponse
extension OCSPResponse {
    struct BasicOCSPResponse {
        let tbsResponseData: ResponseData
        let signatureAlgorithm: SignatureAlgorithm
        /// The signature as DER encoded bytes.
        let signature: [UInt8]
        let certs: [X509Certificate]
        
        init(cbs: UnsafeMutablePointer<CBS>) throws {
            // Parse tbsResponseData
            var tbsResponseDataCBS = CBS()
            guard CNemIDBoringSSL_CBS_get_asn1(cbs, &tbsResponseDataCBS, CBS_ASN1_SEQUENCE) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            
            // Parse signature algorithm
            var signatureAlgorithmCBS = CBS()
            guard CNemIDBoringSSL_CBS_get_asn1(cbs, &signatureAlgorithmCBS, CBS_ASN1_SEQUENCE) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            var algorithmCBS = CBS()
            guard CNemIDBoringSSL_CBS_get_asn1(&signatureAlgorithmCBS, &algorithmCBS, CBS_ASN1_OBJECT) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            let algorithmNID = CNemIDBoringSSL_OBJ_cbs2nid(&algorithmCBS)
            guard let algorithm = BasicOCSPResponse.SignatureAlgorithm(nid: algorithmNID) else {
                throw OCSPResponseError.unknownSignatureAlgorithm(algorithmNID)
            }
            
            // Parse signature
            var signatureCBS = CBS()
            guard CNemIDBoringSSL_CBS_get_asn1(cbs, &signatureCBS, CBS_ASN1_BITSTRING) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            var signatureBytes: UnsafeMutablePointer<UInt8>?
            var signatureLength = 0
            guard CNemIDBoringSSL_CBS_stow(&signatureCBS, &signatureBytes, &signatureLength) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            guard let signatureBytesPtr = signatureBytes else { throw OCSPResponseError.failedToParseResponse }
            defer { CNemIDBoringSSL_OPENSSL_free(signatureBytesPtr) }
            let signature = [UInt8](UnsafeBufferPointer(start: signatureBytesPtr, count: signatureLength))
            
            // Parse certs
            #warning("requires access to nemid to verify...")
            var certsCBS = CBS()
            var isCertsPresent: Int32 = 0
            guard CNemIDBoringSSL_CBS_get_optional_asn1(
                cbs, &certsCBS,
                &isCertsPresent,
                CBS_ASN1_SEQUENCE | CBS_ASN1_CONTEXT_SPECIFIC | 0
            ) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            
            if isCertsPresent == 1 {
                print("certs is present")
            }
            
            self.tbsResponseData = try ResponseData(cbs: &tbsResponseDataCBS)
            self.signatureAlgorithm = algorithm
            self.signature = signature
            self.certs = []
        }
    }
}

// MARK: SignatureAlgorithm
extension OCSPResponse.BasicOCSPResponse {
    enum SignatureAlgorithm {
        case sha256
        case sha1
        
        init?(nid: Int32) {
            switch nid {
            case NID_sha256WithRSAEncryption: self = .sha256
            case NID_sha1WithRSAEncryption: self = .sha1
            default: return nil
            }
        }
    }
}

// MARK: ResponseData
extension OCSPResponse.BasicOCSPResponse {
    struct ResponseData {
        /// Returns the tbsResponseData (self) as DER encoded bytes.
        let derBytes: [UInt8]
        let responses: [SingleResponse]
        
        init(cbs: UnsafeMutablePointer<CBS>) throws {
            var _tbsResponseDataPtr: UnsafeMutablePointer<UInt8>?
            var tbsResponseDataCount = 0
            guard CNemIDBoringSSL_CBS_stow(cbs, &_tbsResponseDataPtr, &tbsResponseDataCount) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            guard let tbsResponseDataPtr = _tbsResponseDataPtr else {
                throw OCSPResponseError.failedToParseResponse
            }
            defer { CNemIDBoringSSL_OPENSSL_free(tbsResponseDataPtr) }
            
            // Ignore responderID
            var responderID = CBS()
            guard CNemIDBoringSSL_CBS_get_any_asn1(cbs, &responderID, nil) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            
            // Ignore producedAt
            var producedAt = CBS()
            guard CNemIDBoringSSL_CBS_get_asn1(cbs, &producedAt, CBS_ASN1_GENERALIZEDTIME) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            
            var responsesCBS = CBS()
            guard CNemIDBoringSSL_CBS_get_asn1(cbs, &responsesCBS, CBS_ASN1_SEQUENCE) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            
            // We expect only 1 response...
            var singleResponseCBS = CBS()
            guard CNemIDBoringSSL_CBS_get_asn1(&responsesCBS, &singleResponseCBS, CBS_ASN1_SEQUENCE) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            
            self.derBytes = [UInt8](UnsafeMutableBufferPointer(start: tbsResponseDataPtr, count: tbsResponseDataCount))
            self.responses = try [SingleResponse(cbs: &singleResponseCBS)]
        }
    }
}

// MARK: SingleResponse
extension OCSPResponse.BasicOCSPResponse.ResponseData {
    struct SingleResponse {
        let certID: CertID
        let certStatus: CertStatus
        let thisUpdate: Date
        let nextUpdate: Date
        
        init(cbs: UnsafeMutablePointer<CBS>) throws {
            // Parse CertID
            var certIDCBS = CBS()
            guard CNemIDBoringSSL_CBS_get_asn1(cbs, &certIDCBS, CBS_ASN1_SEQUENCE) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            
            // Parse CertStatus
            var certStatusCBS = CBS()
            var tag: UInt32 = 0
            guard CNemIDBoringSSL_CBS_get_any_asn1(cbs, &certStatusCBS, &tag) == 1 else { throw OCSPResponseError.failedToParseResponse }
            let tagValue = tag ^ CBS_ASN1_CONTEXT_SPECIFIC
            guard let certStatus = CertStatus(asn1Value: tagValue) else { throw OCSPResponseError.unknownCertStatus(tagValue) }
            
            #warning("convert to dates...")
            // Parse thisUpdate
            var thisUpdateCBS = CBS()
            guard CNemIDBoringSSL_CBS_get_asn1(cbs, &thisUpdateCBS, CBS_ASN1_GENERALIZEDTIME) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            
            // Parse nextUpdate
            var nextUpdateCBS = CBS()
            var isNextUpdatePresent: Int32 = 0
            guard CNemIDBoringSSL_CBS_get_optional_asn1(
                    cbs,
                    &nextUpdateCBS,
                    &isNextUpdatePresent,
                    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 0
            ) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            guard isNextUpdatePresent == 1 else { throw OCSPResponseError.nextUpdateDateWasNotPresent }
            var nextUpdateDateCBS = CBS()
            guard CNemIDBoringSSL_CBS_get_asn1(&nextUpdateCBS, &nextUpdateDateCBS, CBS_ASN1_GENERALIZEDTIME) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            
            self.certID = try CertID(cbs: &certIDCBS)
            self.certStatus = certStatus
            self.nextUpdate = Date()
            self.thisUpdate = Date()
        }
    }
}

// MARK: CertID
extension OCSPResponse.BasicOCSPResponse.ResponseData.SingleResponse {
    struct CertID {
        let hashAlgorithm: HashAlgorithm
        let issuerNameHash: [UInt8]
        let issuerKeyHash: [UInt8]
        let serialNumber: [UInt8]
        
        init(cbs: UnsafeMutablePointer<CBS>) throws {
            // Parse hash algorithm
            var hashAlgorithmCBS = CBS()
            guard CNemIDBoringSSL_CBS_get_asn1(cbs, &hashAlgorithmCBS, CBS_ASN1_SEQUENCE) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            var algorithmCBS = CBS()
            guard CNemIDBoringSSL_CBS_get_asn1(&hashAlgorithmCBS, &algorithmCBS, CBS_ASN1_OBJECT) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            let algorithmNID = CNemIDBoringSSL_OBJ_cbs2nid(&algorithmCBS)
            guard let algorithm = HashAlgorithm(nid: algorithmNID) else {
                throw OCSPResponseError.unknownHashAlgorithm(algorithmNID)
            }
            
            // Parse issuerNameHash
            var issuerNameHashCBS = CBS()
            guard CNemIDBoringSSL_CBS_get_asn1(cbs, &issuerNameHashCBS, CBS_ASN1_OCTETSTRING) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            var _issuerNameHashPtr: UnsafeMutablePointer<UInt8>?
            var issuerNameHashLength = 0
            guard CNemIDBoringSSL_CBS_stow(&issuerNameHashCBS, &_issuerNameHashPtr, &issuerNameHashLength) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            guard let issuerNameHashPtr = _issuerNameHashPtr else {
                throw OCSPResponseError.failedToParseResponse
            }
            defer { CNemIDBoringSSL_OPENSSL_free(issuerNameHashPtr) }
            
            // Parse issuerKeyHash
            var issuerKeyHashCBS = CBS()
            guard CNemIDBoringSSL_CBS_get_asn1(cbs, &issuerKeyHashCBS, CBS_ASN1_OCTETSTRING) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            var _issuerKeyHashPtr: UnsafeMutablePointer<UInt8>?
            var issuerKeyHashLength = 0
            guard CNemIDBoringSSL_CBS_stow(&issuerKeyHashCBS, &_issuerKeyHashPtr, &issuerKeyHashLength) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            guard let issuerKeyHashPtr = _issuerKeyHashPtr else {
                throw OCSPResponseError.failedToParseResponse
            }
            defer { CNemIDBoringSSL_OPENSSL_free(issuerKeyHashPtr) }
            
            #warning("check if this works with NemID")
            // Parse serial number
            var serialNumberCBS = CBS()
            guard CNemIDBoringSSL_CBS_get_asn1(cbs, &serialNumberCBS, CBS_ASN1_INTEGER) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            
            var _serialNumberPtr: UnsafeMutablePointer<UInt8>?
            var serialNumberLength = 0
            guard CNemIDBoringSSL_CBS_stow(&serialNumberCBS, &_serialNumberPtr, &serialNumberLength) == 1 else {
                throw OCSPResponseError.failedToParseResponse
            }
            guard let serialNumberPtr = _serialNumberPtr else { throw OCSPResponseError.failedToParseResponse }
            defer { CNemIDBoringSSL_OPENSSL_free(serialNumberPtr) }
            
            self.hashAlgorithm = algorithm
            self.issuerNameHash = [UInt8](UnsafeMutableBufferPointer(start: issuerNameHashPtr, count: issuerNameHashLength))
            self.issuerKeyHash = [UInt8](UnsafeMutableBufferPointer(start: issuerKeyHashPtr, count: issuerKeyHashLength))
            self.serialNumber = [UInt8](UnsafeMutableBufferPointer(start: serialNumberPtr, count: serialNumberLength))
        }
    }
}

// MARK: HashAlgorithm
extension OCSPResponse.BasicOCSPResponse.ResponseData.SingleResponse.CertID {
    enum HashAlgorithm {
        case sha256
        case sha1
        
        init?(nid: Int32) {
            switch nid {
            case NID_sha256: self = .sha256
            case NID_sha1: self = .sha1
            default: return nil
            }
        }
    }
}

// MARK: CertStatus
extension OCSPResponse.BasicOCSPResponse.ResponseData.SingleResponse {
    enum CertStatus {
        case good
        case revoked
        case unknown
        
        init?(asn1Value: UInt32) {
            switch asn1Value {
            case 0: self = .good
            case 1: self = .revoked
            case 2: self = .unknown
            default: return nil
            }
        }
    }
}

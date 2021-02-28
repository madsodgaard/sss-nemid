#ifndef C_NEMID_SSL_H
#define C_NEMID_SSL_H

#include <CNemIDBoringSSL_x509.h> /* for ossl_x509_add_cert_new() */
#include <CNemIDBoringSSL_asn1.h>
#include <CNemIDBoringSSL_asn1t.h>

/* Field is embedded and not a pointer */
# define ASN1_TFLG_EMBED         (0x1 << 12)

/* Embedded simple type */
# define ASN1_EMBED(stname, field, type) ASN1_EX_TYPE(ASN1_TFLG_EMBED,0, stname, field, type)

typedef struct ocsp_cert_id_st OCSP_CERTID;
typedef struct ocsp_one_request_st OCSP_ONEREQ;
typedef struct ocsp_req_info_st OCSP_REQINFO;
typedef struct ocsp_signature_st OCSP_SIGNATURE;
typedef struct ocsp_request_st OCSP_REQUEST;

/*-  CertID ::= SEQUENCE {
 *       hashAlgorithm            AlgorithmIdentifier,
 *       issuerNameHash     OCTET STRING, -- Hash of Issuer's DN
 *       issuerKeyHash      OCTET STRING, -- Hash of Issuers public key (excluding the tag & length fields)
 *       serialNumber       CertificateSerialNumber }
 */
struct ocsp_cert_id_st {
    X509_ALGOR hashAlgorithm;
    ASN1_OCTET_STRING issuerNameHash;
    ASN1_OCTET_STRING issuerKeyHash;
    ASN1_INTEGER serialNumber;
};

/*-  Request ::=     SEQUENCE {
 *       reqCert                    CertID,
 *       singleRequestExtensions    [0] EXPLICIT Extensions OPTIONAL }
 */
struct ocsp_one_request_st {
    OCSP_CERTID *reqCert;
    STACK_OF(X509_EXTENSION) *singleRequestExtensions;
};

/*-  TBSRequest      ::=     SEQUENCE {
 *       version             [0] EXPLICIT Version DEFAULT v1,
 *       requestorName       [1] EXPLICIT GeneralName OPTIONAL,
 *       requestList             SEQUENCE OF Request,
 *       requestExtensions   [2] EXPLICIT Extensions OPTIONAL }
 */
struct ocsp_req_info_st {
    ASN1_INTEGER *version;
    GENERAL_NAME *requestorName;
    STACK_OF(OCSP_ONEREQ) *requestList;
    STACK_OF(X509_EXTENSION) *requestExtensions;
};

/*-  Signature       ::=     SEQUENCE {
 *       signatureAlgorithm   AlgorithmIdentifier,
 *       signature            BIT STRING,
 *       certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
 */
struct ocsp_signature_st {
    X509_ALGOR signatureAlgorithm;
    ASN1_BIT_STRING *signature;
    STACK_OF(X509) *certs;
};

/*-  OCSPRequest     ::=     SEQUENCE {
 *       tbsRequest                  TBSRequest,
 *       optionalSignature   [0]     EXPLICIT Signature OPTIONAL }
 */
struct ocsp_request_st {
    OCSP_REQINFO tbsRequest;
    OCSP_SIGNATURE *optionalSignature; /* OPTIONAL */
};

DEFINE_STACK_OF(OCSP_CERTID)
DEFINE_STACK_OF(OCSP_ONEREQ)

DECLARE_ASN1_ITEM(OCSP_REQUEST)

DECLARE_ASN1_FUNCTIONS(OCSP_ONEREQ)
DECLARE_ASN1_FUNCTIONS(OCSP_CERTID)
DECLARE_ASN1_FUNCTIONS(OCSP_REQUEST)
DECLARE_ASN1_FUNCTIONS(OCSP_SIGNATURE)
DECLARE_ASN1_FUNCTIONS(OCSP_REQINFO)

#endif

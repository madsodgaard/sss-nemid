@_implementationOnly import CNemIDBoringSSL

// https://github.com/apple/swift-nio-ssl
extension UnsafePointer where Pointee == ASN1_TIME {
    var timeSinceEpoch: time_t {
        let epochTime = CNemIDBoringSSL_ASN1_TIME_new()!
        defer { CNemIDBoringSSL_ASN1_TIME_free(epochTime) }
        
        // This sets the ASN1_TIME to epoch time.
        CNemIDBoringSSL_ASN1_TIME_set(epochTime, 0)
        var day = CInt(0)
        var seconds = CInt(0)
        
        let rc = CNemIDBoringSSL_ASN1_TIME_diff(&day, &seconds, epochTime, self)
        precondition(rc != 0)
        
        // 86400 seconds in a day
        return time_t(day) * 86400 + time_t(seconds)
    }
}

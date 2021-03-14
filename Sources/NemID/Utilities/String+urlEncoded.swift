import Foundation

/* https://github.com/vapor/vapor/blob/062a4088a26ff9e41daacb8aa311f0289232d814/Sources/Vapor/URLEncodedForm/URLEncodedFormSerializer.swift */
extension String {
    /// Prepares a `String` for inclusion in form-urlencoded data.
    func urlEncoded(codingPath: [CodingKey] = []) throws -> String {
        guard let result = self.addingPercentEncoding(
            withAllowedCharacters: _allowedCharacters
        ) else {
            throw EncodingError.invalidValue(self, EncodingError.Context(
                codingPath: codingPath,
                debugDescription: "Unable to add percent encoding to \(self)"
            ))
        }
        return result
    }
}

/// Characters allowed in form-urlencoded data.
private var _allowedCharacters: CharacterSet = {
    var allowed = CharacterSet.urlQueryAllowed
    // these symbols are reserved for url-encoded form
    allowed.remove(charactersIn: "?&=[];+")
    return allowed
}()

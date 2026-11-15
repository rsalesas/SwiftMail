// EMLParser.swift
// Parse raw RFC 822 / EML data into a Message

import Foundation

/// Errors that can occur during EML parsing
public enum EMLParserError: Error, LocalizedError {
    case invalidData
    case missingHeaders
    case malformedHeader(String)

    public var errorDescription: String? {
        switch self {
        case .invalidData:
            return "The data is not valid RFC 822 / EML content"
        case .missingHeaders:
            return "No headers found in the message"
        case .malformedHeader(let detail):
            return "Malformed header: \(detail)"
        }
    }
}

/// Parses raw RFC 822 / EML data into SwiftMail model types.
public struct EMLParser {

    // MARK: - Public API

    /// Parse raw EML data into a ``Message``.
    ///
    /// The returned message uses `SequenceNumber(0)` and `nil` UID because the
    /// data does not originate from an IMAP session.
    ///
    /// - Parameter data: Raw RFC 822 bytes (as obtained from `fetchRawMessage` or an `.eml` file).
    /// - Returns: A fully populated ``Message``.
    public static func parse(_ data: Data) throws -> Message {
        guard !data.isEmpty else {
            throw EMLParserError.invalidData
        }

        // Split headers and body at the first blank line
        let (headerBlock, bodyData) = splitHeadersAndBody(data)

        guard !headerBlock.isEmpty else {
            throw EMLParserError.missingHeaders
        }

        // Parse headers into a dictionary (preserving order isn't critical)
        let headers = parseHeaders(headerBlock)

        // Build MessageInfo
        let info = buildMessageInfo(from: headers)

        // Determine content type of the top-level entity
        let contentType = headers["content-type"] ?? "text/plain"
        let encoding = headers["content-transfer-encoding"]

        // Parse body into parts
        let parts = parseParts(contentType: contentType, encoding: encoding, bodyData: bodyData, sectionPath: [])

        return Message(header: info, parts: parts)
    }

    // MARK: - Header Parsing

    /// Split a raw entity into its header block and its body, at the first
    /// empty line.
    ///
    /// Works on bytes throughout. Finding the separator in a `String` and then
    /// cutting the `Data` at `string.distance(...)` mixed two units: Swift
    /// counts `"\r\n"` as one Character, so in a CRLF message (every message
    /// a mail server hands out) each header line moved the cut one byte early,
    /// and the body began inside the headers. Non-UTF-8 bodies (8bit Latin-1,
    /// binary parts) also made the whole message unparseable, since the body
    /// had to decode as a String first.
    private static func splitHeadersAndBody(_ data: Data) -> (String, Data) {
        let bytes = [UInt8](data)
        let crlf = firstIndex(of: [0x0D, 0x0A, 0x0D, 0x0A], in: bytes, from: 0)
        let lf = firstIndex(of: [0x0A, 0x0A], in: bytes, from: 0)

        // Whichever blank line comes first ends the headers.
        let separator: (start: Int, length: Int)?
        switch (crlf, lf) {
        case let (c?, l?): separator = c <= l ? (c, 4) : (l, 2)
        case let (c?, nil): separator = (c, 4)
        case let (nil, l?): separator = (l, 2)
        case (nil, nil): separator = nil
        }

        guard let separator else {
            // No body — entire content is headers
            return (headerString(bytes[...]), Data())
        }
        return (
            headerString(bytes[..<separator.start]),
            Data(bytes[(separator.start + separator.length)...])
        )
    }

    /// Header bytes as text: UTF-8 (RFC 6532), else Latin-1, which maps every
    /// byte and so never fails on a stray 8-bit header.
    private static func headerString(_ bytes: ArraySlice<UInt8>) -> String {
        String(bytes: bytes, encoding: .utf8) ?? String(bytes: bytes, encoding: .isoLatin1) ?? ""
    }

    /// The first index at or after `start` where `needle` occurs in `haystack`.
    private static func firstIndex(of needle: [UInt8], in haystack: [UInt8], from start: Int) -> Int? {
        guard !needle.isEmpty, haystack.count >= needle.count, start <= haystack.count - needle.count else {
            return nil
        }
        let first = needle[0]
        var index = start
        let last = haystack.count - needle.count
        while index <= last {
            if haystack[index] == first {
                var matched = true
                for offset in 1..<needle.count where haystack[index + offset] != needle[offset] {
                    matched = false
                    break
                }
                if matched { return index }
            }
            index += 1
        }
        return nil
    }

    /// Parse an RFC 5322 header block into key-value pairs.
    /// Handles continuation lines (lines starting with whitespace).
    /// Keys are lowercased for uniform lookup.
    static func parseHeaders(_ block: String) -> [String: String] {
        var headers: [String: String] = [:]
        var currentKey: String?
        var currentValue: String = ""

        let lines = block.components(separatedBy: .newlines)
        for line in lines {
            if line.isEmpty { continue }

            // Continuation line?
            if let first = line.first, first == " " || first == "\t" {
                // Append to current header value (unfolding)
                currentValue += " " + line.trimmingCharacters(in: .whitespaces)
            } else if let colonIndex = line.firstIndex(of: ":") {
                // Save previous header
                if let key = currentKey {
                    headers[key] = currentValue.trimmingCharacters(in: .whitespaces)
                }

                let key = String(line[line.startIndex..<colonIndex]).lowercased().trimmingCharacters(in: .whitespaces)
                let value = String(line[line.index(after: colonIndex)...])
                currentKey = key
                currentValue = value
            }
        }

        // Save last header
        if let key = currentKey {
            headers[key] = currentValue.trimmingCharacters(in: .whitespaces)
        }

        return headers
    }

    /// Parse all headers preserving multiple values for the same key.
    static func parseAllHeaders(_ block: String) -> [(key: String, value: String)] {
        var headers: [(key: String, value: String)] = []
        var currentKey: String?
        var currentValue: String = ""

        let lines = block.components(separatedBy: .newlines)
        for line in lines {
            if line.isEmpty { continue }

            if let first = line.first, first == " " || first == "\t" {
                currentValue += " " + line.trimmingCharacters(in: .whitespaces)
            } else if let colonIndex = line.firstIndex(of: ":") {
                if let key = currentKey {
                    headers.append((key: key, value: currentValue.trimmingCharacters(in: .whitespaces)))
                }

                let key = String(line[line.startIndex..<colonIndex]).lowercased().trimmingCharacters(in: .whitespaces)
                let value = String(line[line.index(after: colonIndex)...])
                currentKey = key
                currentValue = value
            }
        }

        if let key = currentKey {
            headers.append((key: key, value: currentValue.trimmingCharacters(in: .whitespaces)))
        }

        return headers
    }

    // MARK: - MessageInfo Construction

    private static func buildMessageInfo(from headers: [String: String]) -> MessageInfo {
        let from = headers["from"].flatMap { decodeRFC2047($0) } ?? headers["from"]
        let subject = headers["subject"].flatMap { decodeRFC2047($0) } ?? headers["subject"]
        let messageId = headers["message-id"].flatMap { MessageID($0) }

        let to = parseAddressList(headers["to"])
        let cc = parseAddressList(headers["cc"])
        let bcc = parseAddressList(headers["bcc"])

        let date = headers["date"].flatMap { parseRFC2822Date($0) }

        // Threading: replies need both, and they were left behind.
        let inReplyTo = headers["in-reply-to"].flatMap { value in
            value.split(whereSeparator: \.isWhitespace).first.flatMap { MessageID(String($0)) }
        }
        let references = headers["references"].map { value in
            value.split(whereSeparator: \.isWhitespace).compactMap { MessageID(String($0)) }
        }

        // Collect additional headers (everything except standard ones)
        let standardKeys: Set<String> = [
            "from", "to", "cc", "bcc", "subject", "date", "message-id",
            "in-reply-to", "references",
            "content-type", "content-transfer-encoding", "mime-version"
        ]
        var additional: [String: String] = [:]
        for (key, value) in headers where !standardKeys.contains(key) {
            additional[key] = value
        }

        return MessageInfo(
            sequenceNumber: SequenceNumber(0),
            uid: nil,
            subject: subject,
            from: from,
            to: to,
            cc: cc,
            bcc: bcc,
            date: date,
            messageId: messageId,
            inReplyTo: inReplyTo,
            references: references?.isEmpty == false ? references : nil,
            flags: [],
            parts: [],
            additionalFields: additional.isEmpty ? nil : additional
        )
    }

    // MARK: - MIME Body Parsing

    /// Parse the body into MessagePart(s) based on Content-Type.
    private static func parseParts(contentType: String, encoding: String?, bodyData: Data, sectionPath: [Int]) -> [MessagePart] {
        let ct = contentType.lowercased()

        if ct.hasPrefix("multipart/") {
            return parseMultipart(contentType: contentType, bodyData: bodyData, sectionPath: sectionPath)
        } else {
            // Single part
            let section = sectionPath.isEmpty ? [1] : sectionPath
            let disposition = extractHeaderParam(from: contentType, named: "disposition")
            let filename = extractFilename(from: contentType)

            let part = MessagePart(
                section: Section(section),
                contentType: cleanContentType(contentType),
                disposition: disposition,
                encoding: encoding,
                filename: filename,
                contentId: nil,
                data: bodyData
            )
            return [part]
        }
    }

    /// Parse a multipart body, splitting by boundary.
    private static func parseMultipart(contentType: String, bodyData: Data, sectionPath: [Int]) -> [MessagePart] {
        guard let boundary = extractBoundary(from: contentType) else {
            // Can't parse without boundary — treat as opaque
            let section = sectionPath.isEmpty ? [1] : sectionPath
            return [MessagePart(
                section: Section(section),
                contentType: extractMIMEType(from: contentType),
                data: bodyData
            )]
        }

        let rawParts = splitMultipartBody([UInt8](bodyData), boundary: boundary)

        // Parse each sub-part
        var result: [MessagePart] = []
        for (index, rawPart) in rawParts.enumerated() {
            let partNumber = index + 1
            let childPath = sectionPath.isEmpty ? [partNumber] : sectionPath + [partNumber]

            let (partHeaders, partBody) = splitHeadersAndBody(rawPart)
            let headers = parseHeaders(partHeaders)

            let partContentType = headers["content-type"] ?? "text/plain"
            let partEncoding = headers["content-transfer-encoding"]
            let partDisposition = headers["content-disposition"]
            let partContentId = headers["content-id"]?.trimmingCharacters(in: .init(charactersIn: "<>"))

            let filename = extractFilename(from: partContentType) ?? extractFilename(from: partDisposition ?? "")

            if partContentType.lowercased().hasPrefix("multipart/") {
                // Recursive multipart
                let nested = parseMultipart(contentType: partContentType, bodyData: partBody, sectionPath: childPath)
                result.append(contentsOf: nested)
            } else {
                let part = MessagePart(
                    section: Section(childPath),
                    contentType: cleanContentType(partContentType),
                    disposition: extractDispositionType(from: partDisposition),
                    encoding: partEncoding?.trimmingCharacters(in: .whitespaces),
                    filename: (filename != nil ? decodeRFC2047(filename!) : nil),
                    contentId: partContentId,
                    data: partBody
                )
                result.append(part)
            }
        }

        return result
    }

    /// The body parts of a multipart entity, as bytes, between its boundaries.
    ///
    /// A delimiter counts only at the start of a line (RFC 2046 §5.1.1), and
    /// the line break before it belongs to the delimiter, not to the part.
    /// Byte offsets throughout, for the reason given at `splitHeadersAndBody`.
    static func splitMultipartBody(_ bytes: [UInt8], boundary: String) -> [Data] {
        let delimiter = Array("--\(boundary)".utf8)
        let cr: UInt8 = 0x0D, lf: UInt8 = 0x0A, dash: UInt8 = 0x2D

        // Every delimiter that starts a line.
        var delimiters: [Int] = []
        var searchFrom = 0
        while let found = firstIndex(of: delimiter, in: bytes, from: searchFrom) {
            if found == 0 || bytes[found - 1] == lf { delimiters.append(found) }
            searchFrom = found + delimiter.count
        }

        var parts: [Data] = []
        for (position, start) in delimiters.enumerated() {
            let afterDelimiter = start + delimiter.count
            // The close delimiter ends the multipart; what follows is epilogue.
            if afterDelimiter + 1 < bytes.count, bytes[afterDelimiter] == dash, bytes[afterDelimiter + 1] == dash {
                break
            }
            // Skip transport padding and the line break after the delimiter.
            var contentStart = afterDelimiter
            while contentStart < bytes.count, bytes[contentStart] == 0x20 || bytes[contentStart] == 0x09 {
                contentStart += 1
            }
            if contentStart < bytes.count, bytes[contentStart] == cr { contentStart += 1 }
            if contentStart < bytes.count, bytes[contentStart] == lf { contentStart += 1 }

            if position + 1 < delimiters.count {
                var contentEnd = delimiters[position + 1]
                if contentEnd > contentStart, bytes[contentEnd - 1] == lf {
                    contentEnd -= 1
                    if contentEnd > contentStart, bytes[contentEnd - 1] == cr { contentEnd -= 1 }
                }
                parts.append(Data(bytes[contentStart..<max(contentStart, contentEnd)]))
            } else {
                // No close delimiter: the rest is the last part.
                var contentEnd = bytes.count
                while contentEnd > contentStart, bytes[contentEnd - 1] == cr || bytes[contentEnd - 1] == lf {
                    contentEnd -= 1
                }
                parts.append(Data(bytes[contentStart..<contentEnd]))
            }
        }
        return parts
    }

    // MARK: - Header Parameter Extraction

    /// Extract the MIME type (e.g. "text/html") from a full Content-Type value.
    static func extractMIMEType(from contentType: String) -> String {
        let parts = contentType.split(separator: ";", maxSplits: 1)
        return parts.first.map { String($0).trimmingCharacters(in: .whitespaces) } ?? contentType
    }

    /// Clean a Content-Type value for storage in MessagePart.
    /// Preserves charset and other relevant params, strips name/filename/boundary.
    static func cleanContentType(_ contentType: String) -> String {
        let components = contentType.split(separator: ";")
        guard let mimeType = components.first else { return contentType }

        var result = String(mimeType).trimmingCharacters(in: .whitespaces)
        let skipParams: Set<String> = ["name", "filename", "boundary"]

        for component in components.dropFirst() {
            let trimmed = String(component).trimmingCharacters(in: .whitespaces)
            let paramName = trimmed.split(separator: "=", maxSplits: 1).first
                .map { String($0).trimmingCharacters(in: .whitespaces).lowercased() } ?? ""
            if !skipParams.contains(paramName) {
                result += "; \(trimmed)"
            }
        }

        return result
    }

    /// Extract the boundary parameter from a Content-Type header.
    static func extractBoundary(from contentType: String) -> String? {
        return extractHeaderParam(from: contentType, named: "boundary")
    }

    /// Extract a named parameter from a header value (e.g. `boundary="abc"` → `abc`).
    static func extractHeaderParam(from header: String, named name: String) -> String? {
        // Case-insensitive search for name=value or name="value"
        let pattern = name + "="
        guard let range = header.range(of: pattern, options: .caseInsensitive) else {
            return nil
        }

        var value = String(header[range.upperBound...]).trimmingCharacters(in: .whitespaces)

        // Remove quotes
        if value.hasPrefix("\"") {
            value.removeFirst()
            if let endQuote = value.firstIndex(of: "\"") {
                value = String(value[value.startIndex..<endQuote])
            }
        } else {
            // Unquoted — take until semicolon or end
            if let semi = value.firstIndex(of: ";") {
                value = String(value[value.startIndex..<semi])
            }
            value = value.trimmingCharacters(in: .whitespaces)
        }

        return value
    }

    /// Extract filename from Content-Type or Content-Disposition header.
    static func extractFilename(from header: String) -> String? {
        // Try filename* (RFC 5987 extended) first, then filename, then name
        if let filename = extractHeaderParam(from: header, named: "filename*") {
            // Strip encoding prefix like "UTF-8''filename.txt"
            if let idx = filename.range(of: "''") {
                return String(filename[idx.upperBound...]).removingPercentEncoding ?? String(filename[idx.upperBound...])
            }
            return filename
        }

        return extractHeaderParam(from: header, named: "filename")
            ?? extractHeaderParam(from: header, named: "name")
    }

    /// Extract the disposition type (e.g. "attachment", "inline") from Content-Disposition.
    static func extractDispositionType(from disposition: String?) -> String? {
        guard let disp = disposition else { return nil }
        let parts = disp.split(separator: ";", maxSplits: 1)
        return parts.first.map { String($0).trimmingCharacters(in: .whitespaces).lowercased() }
    }

    // MARK: - Address Parsing

    /// Parse a comma-separated list of email addresses.
    static func parseAddressList(_ value: String?) -> [String] {
        guard let value = value, !value.isEmpty else { return [] }

        // Split by comma, but respect quoted strings and angle brackets
        var addresses: [String] = []
        var current = ""
        var inQuotes = false
        var inAngle = false

        for char in value {
            switch char {
            case "\"":
                inQuotes.toggle()
                current.append(char)
            case "<":
                inAngle = true
                current.append(char)
            case ">":
                inAngle = false
                current.append(char)
            case "," where !inQuotes && !inAngle:
                let trimmed = current.trimmingCharacters(in: .whitespaces)
                if !trimmed.isEmpty {
                    addresses.append(decodeRFC2047(trimmed) ?? trimmed)
                }
                current = ""
            default:
                current.append(char)
            }
        }

        let trimmed = current.trimmingCharacters(in: .whitespaces)
        if !trimmed.isEmpty {
            addresses.append(decodeRFC2047(trimmed) ?? trimmed)
        }

        return addresses
    }

    // MARK: - Date Parsing

    /// Parse an RFC 2822 date string.
    static func parseRFC2822Date(_ string: String) -> Date? {
        let trimmed = string.trimmingCharacters(in: .whitespaces)
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")

        let formats = [
            "EEE, dd MMM yyyy HH:mm:ss Z",       // Standard RFC 2822
            "EEE, d MMM yyyy HH:mm:ss Z",        // Single-digit day
            "dd MMM yyyy HH:mm:ss Z",            // No day name
            "d MMM yyyy HH:mm:ss Z",             // No day name, single-digit day
            "EEE, dd MMM yyyy HH:mm:ss ZZZZ",    // Named timezone
            "EEE, d MMM yyyy HH:mm:ss ZZZZ",
            "EEE, dd MMM yy HH:mm:ss Z",         // Two-digit year
        ]

        for format in formats {
            formatter.dateFormat = format
            if let date = formatter.date(from: trimmed) {
                return date
            }
        }

        // Try ISO 8601 as fallback
        let iso = ISO8601DateFormatter()
        return iso.date(from: trimmed)
    }

    // MARK: - RFC 2047 Encoded Word Decoding

    /// Decode RFC 2047 encoded words (=?charset?encoding?text?=).
    static func decodeRFC2047(_ input: String) -> String? {
        let pattern = "=\\?([^?]+)\\?([BbQq])\\?([^?]*)\\?="

        guard let regex = try? NSRegularExpression(pattern: pattern) else {
            return input
        }

        let nsInput = input as NSString
        let matches = regex.matches(in: input, range: NSRange(location: 0, length: nsInput.length))

        if matches.isEmpty {
            return input
        }

        var result = input
        // Process matches in reverse to preserve indices
        for match in matches.reversed() {
            guard match.numberOfRanges >= 4 else { continue }

            let fullMatch = nsInput.substring(with: match.range)
            let charset = nsInput.substring(with: match.range(at: 1))
            let encodingChar = nsInput.substring(with: match.range(at: 2)).uppercased()
            let encodedText = nsInput.substring(with: match.range(at: 3))

            let encoding = String.Encoding.fromCharsetName(charset) ?? .utf8

            var decoded: String?
            if encodingChar == "B" {
                // Base64
                if let data = Data(base64Encoded: encodedText) {
                    decoded = String(data: data, encoding: encoding)
                }
            } else if encodingChar == "Q" {
                // Quoted-printable (underscore = space)
                let qpString = encodedText.replacingOccurrences(of: "_", with: " ")
                decoded = decodeQP(qpString, encoding: encoding)
            }

            if let decoded = decoded {
                result = result.replacingOccurrences(of: fullMatch, with: decoded)
            }
        }

        return result
    }

    /// Decode a quoted-printable string with a specific encoding.
    private static func decodeQP(_ input: String, encoding: String.Encoding) -> String? {
        var bytes: [UInt8] = []
        var index = input.startIndex

        while index < input.endIndex {
            let char = input[index]
            if char == "=" {
                let next1 = input.index(index, offsetBy: 1, limitedBy: input.endIndex)
                let next2 = next1.flatMap { input.index($0, offsetBy: 1, limitedBy: input.endIndex) }

                if let n1 = next1, next2 != nil {
                    // Decode two hex chars after "=" into a single byte.
                    let hexStr = String(input[n1]) + String(input[input.index(after: n1)])
                    if let byte = UInt8(hexStr, radix: 16) {
                        bytes.append(byte)
                        index = input.index(index, offsetBy: 3)
                        continue
                    }
                }
            }

            // Regular character
            for byte in String(char).utf8 {
                bytes.append(byte)
            }
            index = input.index(after: index)
        }

        return String(data: Data(bytes), encoding: encoding)
    }
}

// MARK: - String.Encoding helper

extension String.Encoding {
    /// Map a charset name to a String.Encoding.
    static func fromCharsetName(_ name: String) -> String.Encoding? {
        switch name.lowercased() {
        case "utf-8", "utf8":
            return .utf8
        case "iso-8859-1", "latin1", "iso_8859-1":
            return .isoLatin1
        case "iso-8859-2", "latin2", "iso_8859-2":
            return .isoLatin2
        case "us-ascii", "ascii":
            return .ascii
        case "windows-1252", "cp1252":
            return .windowsCP1252
        case "windows-1250", "cp1250":
            return .windowsCP1250
        case "iso-8859-15", "latin9", "iso_8859-15":
            return .isoLatin1 // Close enough
        default:
            return nil
        }
    }
}

// MARK: - Message convenience initializer

public extension Message {
    /// Initialize a Message by parsing raw EML / RFC 822 data.
    ///
    /// - Parameter emlData: The raw message bytes.
    /// - Throws: ``EMLParserError`` if parsing fails.
    init(emlData: Data) throws {
        self = try EMLParser.parse(emlData)
    }
}

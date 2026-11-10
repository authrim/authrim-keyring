import Foundation

/// Rejects active and externally referencing SVG before it is ever stored as card artwork.
/// The UI additionally loads it as an image in a WebKit page with scripts and networking blocked.
nonisolated final class SVGImageValidator: NSObject, XMLParserDelegate {
    private static let forbiddenElements: Set<String> = [
        "script", "foreignobject", "iframe", "object", "embed", "video", "audio",
        "animate", "animatetransform", "animatemotion", "set",
    ]

    private var valid = true
    private var sawRoot = false
    private var depth = 0
    private var elements = 0
    private var styleText = ""
    private var inStyle = false

    static func isSafe(_ data: Data) -> Bool {
        guard !data.isEmpty, data.count <= CredentialDisplayMetadata.backgroundLimit,
              let text = String(data: data, encoding: .utf8) else { return false }
        let lower = text.lowercased()
        guard !lower.contains("<!doctype"), !lower.contains("<!entity"), !lower.contains("<?xml-stylesheet")
        else { return false }
        let validator = SVGImageValidator()
        let parser = XMLParser(data: data)
        parser.delegate = validator
        parser.shouldProcessNamespaces = true
        parser.shouldResolveExternalEntities = false
        return parser.parse() && validator.valid && validator.sawRoot && validator.depth == 0 &&
            safeCSS(validator.styleText)
    }

    /// Replace claim placeholders only in XML character data. Reject tokens in tags, attributes,
    /// comments and CDATA; a claim can therefore never become a URL, style, or event handler.
    static func renderTemplate(_ data: Data, values: [String: String]) -> Data? {
        guard isSafe(data), let input = String(data: data, encoding: .utf8) else { return nil }
        var remaining = input[...]
        var result = ""
        while !remaining.isEmpty {
            if remaining.first == "<" {
                let end: Substring.Index
                if remaining.hasPrefix("<!--") {
                    guard let range = remaining.range(of: "-->") else { return nil }
                    end = range.upperBound
                } else if remaining.hasPrefix("<![CDATA[") {
                    guard let range = remaining.range(of: "]]>") else { return nil }
                    end = range.upperBound
                } else {
                    var quote: Character?
                    var cursor = remaining.startIndex
                    var close: Substring.Index?
                    while cursor < remaining.endIndex {
                        let character = remaining[cursor]
                        if let delimiter = quote {
                            if character == delimiter { quote = nil }
                        } else if character == "\"" || character == "'" {
                            quote = character
                        } else if character == ">" {
                            close = remaining.index(after: cursor)
                            break
                        }
                        cursor = remaining.index(after: cursor)
                    }
                    guard let close else { return nil }
                    end = close
                }
                let markup = remaining[..<end]
                guard !markup.contains("{{"), !markup.contains("}}") else { return nil }
                result += markup
                remaining = remaining[end...]
            } else {
                let end = remaining.firstIndex(of: "<") ?? remaining.endIndex
                guard let replaced = replaceText(String(remaining[..<end]), values: values) else { return nil }
                result += replaced
                remaining = remaining[end...]
            }
            guard result.utf8.count <= CredentialDisplayMetadata.backgroundLimit else { return nil }
        }
        let output = Data(result.utf8)
        return isSafe(output) ? output : nil
    }

    private static func replaceText(_ text: String, values: [String: String]) -> String? {
        let pattern = #"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}"#
        guard let expression = try? NSRegularExpression(pattern: pattern) else { return nil }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        var result = text
        for match in expression.matches(in: text, range: range).reversed() {
            guard let idRange = Range(match.range(at: 1), in: text),
                  let wholeRange = Range(match.range, in: result),
                  let raw = values[String(text[idRange])], xmlTextIsValid(raw) else { return nil }
            result.replaceSubrange(wholeRange, with: escape(raw))
        }
        guard !result.contains("{{"), !result.contains("}}") else { return nil }
        return result
    }

    private static func xmlTextIsValid(_ text: String) -> Bool {
        text.unicodeScalars.allSatisfy { scalar in
            let value = scalar.value
            return value == 0x9 || value == 0xA || value == 0xD ||
                (0x20...0xD7FF).contains(value) || (0xE000...0xFFFD).contains(value) ||
                (0x10000...0x10FFFF).contains(value)
        }
    }

    private static func escape(_ text: String) -> String {
        text.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&apos;")
    }

    func parser(
        _ parser: XMLParser, didStartElement elementName: String,
        namespaceURI: String?, qualifiedName qName: String?, attributes attributeDict: [String: String]
    ) {
        let element = elementName.lowercased()
        if !sawRoot {
            sawRoot = element == "svg" && namespaceURI == "http://www.w3.org/2000/svg"
            if !sawRoot { valid = false; parser.abortParsing(); return }
        }
        depth += 1
        elements += 1
        if depth > 64 || elements > 1_000 || Self.forbiddenElements.contains(element) ||
            attributeDict.count > 64 {
            valid = false; parser.abortParsing(); return
        }
        if element == "style" { inStyle = true }
        for (name, value) in attributeDict {
            let key = name.lowercased()
            let lowerValue = value.lowercased()
            if key.hasPrefix("on") || key == "xml:base" ||
                !Self.safeCSS(value) ||
                (!(key == "xmlns" || key.hasPrefix("xmlns:")) &&
                 (lowerValue.contains("http:") || lowerValue.contains("https:"))) {
                valid = false; parser.abortParsing(); return
            }
            if key == "href" || key == "xlink:href" {
                let address = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                if !(address.hasPrefix("#") || address.hasPrefix("data:image/png;") ||
                     address.hasPrefix("data:image/jpeg;")) {
                    valid = false; parser.abortParsing(); return
                }
            }
        }
    }

    func parser(_ parser: XMLParser, didEndElement elementName: String,
                namespaceURI: String?, qualifiedName qName: String?) {
        if elementName.lowercased() == "style" { inStyle = false }
        depth -= 1
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        if inStyle {
            if string.contains("{{") || string.contains("}}") {
                valid = false
                parser.abortParsing()
            }
            styleText += string
        }
    }

    func parser(_ parser: XMLParser, foundCDATA CDATABlock: Data) {
        valid = false
        parser.abortParsing()
    }

    func parser(_ parser: XMLParser, foundProcessingInstructionWithTarget target: String, data: String?) {
        valid = false
        parser.abortParsing()
    }

    private static func safeCSS(_ text: String) -> Bool {
        let lower = text.lowercased()
        guard !lower.contains("@import"), !lower.contains("expression("),
              !lower.contains("http:"), !lower.contains("https:") else { return false }
        var remaining = lower[...]
        while let range = remaining.range(of: "url(") {
            remaining = remaining[range.upperBound...]
            let argument = remaining.drop(while: { $0.isWhitespace || $0 == "'" || $0 == "\"" })
            guard argument.first == "#", let close = argument.firstIndex(of: ")") else { return false }
            remaining = argument[argument.index(after: close)...]
        }
        return true
    }
}

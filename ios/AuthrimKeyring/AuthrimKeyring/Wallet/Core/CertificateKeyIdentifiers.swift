import Foundation

/// Reads extensions of a DER certificate: the `keyIdentifier` of the Authority Key Identifier (RFC 5280
/// 4.2.1.1, OID 2.5.29.35), which an OpenID4VP DCQL `trusted_authorities` entry of type `aki` is
/// matched against, and the presence of an extension by OID.
nonisolated enum CertificateKeyIdentifiers {
    private struct Extension { let oid: [UInt8]; let value: Range<Int> }

    static func authorityKeyIdentifier(of certificateDER: Data) -> Data? {
        let bytes = Array(certificateDER)
        guard let found = extensions(in: bytes)?.first(where: { $0.oid == [0x55, 0x1D, 0x23] }) else { return nil }
        var content = Reader(bytes, found.value)
        guard let aki = content.read(tag: 0x30) else { return nil }
        var parts = Reader(bytes, aki)
        while !parts.isAtEnd {
            guard let part = parts.read() else { return nil }
            if part.tag == 0x80 { return Data(bytes[part.value]) } // [0] keyIdentifier
        }
        return nil
    }

    /// Whether the certificate has an extension with this DER OID value. A certificate that cannot be
    /// parsed counts as having it, so a caller that refuses the extension also refuses a broken one.
    static func hasExtension(oid wanted: [UInt8], in certificateDER: Data) -> Bool {
        guard let list = extensions(in: Array(certificateDER)) else { return true }
        return list.contains { $0.oid == wanted }
    }

    /// All extensions (empty when the certificate has none), or nil when the DER is malformed.
    private static func extensions(in bytes: [UInt8]) -> [Extension]? {
        var document = Reader(bytes, 0..<bytes.count)
        guard let certificate = document.read(tag: 0x30), document.isAtEnd else { return nil }
        var outer = Reader(bytes, certificate)
        guard let tbs = outer.read(tag: 0x30) else { return nil }
        var fields = Reader(bytes, tbs)
        if fields.nextTag == 0xA0 { guard fields.read(tag: 0xA0) != nil else { return nil } }
        for tag: UInt8 in [0x02, 0x30, 0x30, 0x30, 0x30, 0x30] { guard fields.read(tag: tag) != nil else { return nil } }
        var region: Range<Int>?
        while !fields.isAtEnd {
            guard let element = fields.read() else { return nil }
            if element.tag == 0xA3 { region = element.value }
        }
        guard let region else { return [] }
        var explicit = Reader(bytes, region)
        guard let sequence = explicit.read(tag: 0x30) else { return nil }
        var items = Reader(bytes, sequence)
        var result: [Extension] = []
        while !items.isAtEnd {
            guard let item = items.read(tag: 0x30) else { return nil }
            var ext = Reader(bytes, item)
            guard let oid = ext.read(tag: 0x06) else { return nil }
            if ext.nextTag == 0x01 { guard ext.read(tag: 0x01) != nil else { return nil } }
            guard let value = ext.read(tag: 0x04) else { return nil }
            result.append(Extension(oid: Array(bytes[oid]), value: value))
        }
        return result
    }

    private struct Reader {
        let bytes: [UInt8]
        let end: Int
        var position: Int
        init(_ bytes: [UInt8], _ range: Range<Int>) {
            self.bytes = bytes
            position = range.lowerBound
            end = range.upperBound
        }
        var isAtEnd: Bool { position == end }
        var nextTag: UInt8? { position < end ? bytes[position] : nil }
        mutating func read(tag expected: UInt8) -> Range<Int>? {
            guard let element = read(), element.tag == expected else { return nil }
            return element.value
        }
        mutating func read() -> (tag: UInt8, value: Range<Int>)? {
            guard position + 2 <= end else { return nil }
            let tag = bytes[position]
            position += 1
            let first = bytes[position]
            position += 1
            var length = Int(first)
            if first & 0x80 != 0 {
                let octets = Int(first & 0x7F)
                guard (1...4).contains(octets), position + octets <= end else { return nil }
                length = 0
                for _ in 0..<octets { length = (length << 8) | Int(bytes[position]); position += 1 }
            }
            guard length <= end - position else { return nil }
            let value = position..<(position + length)
            position += length
            return (tag, value)
        }
    }
}

import Foundation

/// Reads the `otpauth-migration://offline?data=…` QR codes Google Authenticator
/// shows under “Transfer accounts”. The data is a small protocol buffer.
nonisolated enum GoogleAuthMigration {
    /// One of the QR codes; a large transfer is split across several.
    struct Batch: Sendable {
        var accounts: ImportedAccounts
        /// Position of this code among `size`, counted from zero.
        var index: Int
        var size: Int
        /// Shared by every code of one transfer.
        var id: Int
    }

    /// More codes than any real transfer uses, so a crafted one cannot grow without end.
    static let maximumCodes = 50

    static func isMigrationURI(_ text: String) -> Bool {
        text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().hasPrefix("otpauth-migration:")
    }

    static func parse(_ text: String) throws(ImportError) -> Batch {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: trimmed),
              components.scheme?.lowercased() == "otpauth-migration",
              let encoded = components.queryItems?.first(where: { $0.name == "data" })?.value
        else { throw .unrecognized }
        guard encoded.count <= 64 * 1024 else { throw .tooLarge }
        guard let data = Data(base64Encoded: padded(encoded)) else { throw .damaged }

        var reader = ProtobufReader(data)
        var result = ImportedAccounts()
        var batch = Batch(accounts: ImportedAccounts(), index: 0, size: 1, id: 0)
        do {
            while let (field, value) = try reader.next() {
                switch (field, value) {
                case (1, .bytes(let entry)):
                    guard result.accounts.count + result.skipped.count < ImportedAccounts.maximumEntries else { throw ImportError.tooLarge }
                    try readEntry(entry, into: &result)
                case (3, .varint(let size)):
                    batch.size = max(1, Int(clamping: size))
                    guard batch.size <= maximumCodes else { throw ImportError.tooLarge }
                case (4, .varint(let index)):
                    batch.index = Int(clamping: index)
                case (5, .varint(let id)):
                    batch.id = Int(truncatingIfNeeded: id)
                default:
                    continue
                }
            }
        } catch let error as ImportError {
            throw error
        } catch {
            throw .damaged
        }
        guard batch.index < batch.size else { throw .damaged }
        batch.accounts = result
        return batch
    }

    private static func readEntry(_ data: Data, into result: inout ImportedAccounts) throws {
        var reader = ProtobufReader(data)
        var secret = Data()
        var name = ""
        var issuer = ""
        var algorithm: UInt64 = 0
        var digits: UInt64 = 0
        var type: UInt64 = 0
        while let (field, value) = try reader.next() {
            switch (field, value) {
            case (1, .bytes(let bytes)): secret = bytes
            case (2, .bytes(let bytes)): name = String(decoding: bytes, as: UTF8.self)
            case (3, .bytes(let bytes)): issuer = String(decoding: bytes, as: UTF8.self)
            case (4, .varint(let value)): algorithm = value
            case (5, .varint(let value)): digits = value
            case (6, .varint(let value)): type = value
            default: continue
            }
        }

        // The name may repeat the issuer as "Issuer:account", like a key URI label.
        var accountName = name
        if let colon = name.firstIndex(of: ":") {
            let prefix = name[..<colon].trimmingCharacters(in: .whitespaces)
            if issuer.isEmpty || prefix == issuer {
                if issuer.isEmpty { issuer = prefix }
                accountName = name[name.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            }
        }
        let label = [issuer, accountName].filter { !$0.isEmpty }.joined(separator: " – ")

        // 1 is HOTP, which needs a counter this app does not keep; 0 is unspecified.
        switch type {
        case 0, 2:
            break
        case 1:
            result.skip(label, reason: String(localized: "Counter-based (HOTP) codes are not supported."))
            return
        default:
            result.skip(label, reason: String(localized: "This kind of code is not supported."))
            return
        }
        // 0 is unspecified, 1 six digits, 2 eight digits.
        guard digits <= 2 else {
            result.skip(label, reason: String(localized: "This number of digits is not supported."))
            return
        }
        let parsedAlgorithm: OTPAlgorithm
        switch algorithm {
        case 0, 1: parsedAlgorithm = .sha1
        case 2: parsedAlgorithm = .sha256
        case 3: parsedAlgorithm = .sha512
        default:
            result.skip(label, reason: String(localized: "The algorithm is not supported."))
            return
        }
        let account = OTPAccount(
            issuer: issuer,
            accountName: accountName,
            secret: secret,
            algorithm: parsedAlgorithm,
            // 2 is eight digits; 0 and 1 are six.
            digits: digits == 2 ? 8 : 6,
            period: 30
        )
        result.add(account, label: label)
    }

    /// The URL carries standard Base64, sometimes without its padding.
    private static func padded(_ text: String) -> String {
        let remainder = text.count % 4
        return remainder == 0 ? text : text + String(repeating: "=", count: 4 - remainder)
    }
}

/// The few protocol buffer wire types the migration payload uses.
nonisolated struct ProtobufReader {
    enum Value {
        case varint(UInt64)
        case bytes(Data)
        case other
    }

    struct Malformed: Error {}

    private let data: [UInt8]
    private var offset = 0

    init(_ data: Data) {
        self.data = Array(data)
    }

    /// The next field number and value, or nil at the end.
    mutating func next() throws -> (Int, Value)? {
        guard offset < data.count else { return nil }
        let key = try readVarint()
        let field = Int(key >> 3)
        guard field > 0 else { throw Malformed() }
        switch key & 0x7 {
        case 0:
            return (field, .varint(try readVarint()))
        case 1:
            try skip(8)
            return (field, .other)
        case 2:
            let length = try readVarint()
            guard length <= UInt64(data.count - offset) else { throw Malformed() }
            let start = offset
            offset += Int(length)
            return (field, .bytes(Data(data[start..<offset])))
        case 5:
            try skip(4)
            return (field, .other)
        default:
            throw Malformed()
        }
    }

    private mutating func readVarint() throws -> UInt64 {
        var result: UInt64 = 0
        var shift: UInt64 = 0
        while true {
            guard offset < data.count, shift < 64 else { throw Malformed() }
            let byte = data[offset]
            offset += 1
            // The tenth byte holds only the 64th bit.
            guard shift < 63 || byte <= 1 else { throw Malformed() }
            result |= UInt64(byte & 0x7F) << shift
            if byte & 0x80 == 0 { return result }
            shift += 7
        }
    }

    private mutating func skip(_ count: Int) throws {
        guard count <= data.count - offset else { throw Malformed() }
        offset += count
    }
}

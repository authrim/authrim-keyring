import Foundation

/// RFC 4648 Base32 decoding, tolerant of the formatting users paste from setup pages
/// (lowercase, spaces, hyphens and missing padding).
nonisolated enum Base32 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    private static let lookup: [Character: UInt8] = {
        var table: [Character: UInt8] = [:]
        for (index, char) in alphabet.enumerated() {
            table[char] = UInt8(index)
        }
        return table
    }()

    static func normalize(_ input: String) -> String {
        input.uppercased().filter { !$0.isWhitespace && $0 != "-" && $0 != "=" }
    }

    static func decode(_ input: String) -> Data? {
        let cleaned = normalize(input)
        guard !cleaned.isEmpty else { return nil }
        // Lengths 1, 3 and 6 (mod 8) cannot be produced by a valid encoder.
        guard ![1, 3, 6].contains(cleaned.count % 8) else { return nil }

        var output = Data()
        output.reserveCapacity(cleaned.count * 5 / 8)
        var buffer: UInt32 = 0
        var bitsLeft = 0
        for char in cleaned {
            guard let value = lookup[char] else { return nil }
            buffer = (buffer << 5) | UInt32(value)
            bitsLeft += 5
            if bitsLeft >= 8 {
                bitsLeft -= 8
                output.append(UInt8((buffer >> UInt32(bitsLeft)) & 0xFF))
            }
        }
        return output
    }

    static func encode(_ data: Data) -> String {
        var output = ""
        var buffer: UInt32 = 0
        var bitsLeft = 0
        for byte in data {
            buffer = (buffer << 8) | UInt32(byte)
            bitsLeft += 8
            while bitsLeft >= 5 {
                bitsLeft -= 5
                output.append(alphabet[Int((buffer >> UInt32(bitsLeft)) & 0x1F)])
            }
        }
        if bitsLeft > 0 {
            output.append(alphabet[Int((buffer << UInt32(5 - bitsLeft)) & 0x1F)])
        }
        return output
    }
}

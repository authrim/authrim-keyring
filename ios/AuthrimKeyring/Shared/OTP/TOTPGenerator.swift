import CryptoKit
import Foundation

/// RFC 6238 time-based one-time passwords built on the RFC 4226 HOTP truncation.
enum TOTPGenerator {
    struct Code: Equatable {
        let value: String
        /// Start of the time step that produced this code.
        let validFrom: Date
        let validUntil: Date

        func secondsRemaining(at date: Date) -> TimeInterval {
            max(0, validUntil.timeIntervalSince(date))
        }
    }

    static func code(for account: OTPAccount, at date: Date = .now) -> Code {
        code(secret: account.secret, algorithm: account.algorithm, digits: account.digits, period: account.period, at: date)
    }

    static func code(secret: Data, algorithm: OTPAlgorithm, digits: Int, period: Int, at date: Date) -> Code {
        let period = max(period, 1)
        let seconds = max(0, date.timeIntervalSince1970)
        let counter = UInt64(seconds) / UInt64(period)
        let start = Date(timeIntervalSince1970: TimeInterval(counter * UInt64(period)))
        return Code(
            value: hotp(secret: secret, counter: counter, algorithm: algorithm, digits: digits),
            validFrom: start,
            validUntil: start.addingTimeInterval(TimeInterval(period))
        )
    }

    static func hotp(secret: Data, counter: UInt64, algorithm: OTPAlgorithm, digits: Int) -> String {
        let message = withUnsafeBytes(of: counter.bigEndian) { Data($0) }
        let key = SymmetricKey(data: secret)
        let mac: [UInt8] = switch algorithm {
        case .sha1: Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
        case .sha256: Array(HMAC<SHA256>.authenticationCode(for: message, using: key))
        case .sha512: Array(HMAC<SHA512>.authenticationCode(for: message, using: key))
        }

        let offset = Int(mac[mac.count - 1] & 0x0F)
        let truncated = (UInt32(mac[offset] & 0x7F) << 24)
            | (UInt32(mac[offset + 1]) << 16)
            | (UInt32(mac[offset + 2]) << 8)
            | UInt32(mac[offset + 3])

        var modulus: UInt32 = 1
        for _ in 0..<digits { modulus *= 10 }
        let value = truncated % modulus
        let text = String(value)
        return String(repeating: "0", count: max(0, digits - text.count)) + text
    }

    /// Splits a code into two halves for readability, e.g. "123 456".
    static func formatted(_ value: String) -> String {
        guard value.count >= 6 else { return value }
        let mid = value.index(value.startIndex, offsetBy: value.count / 2)
        return "\(value[..<mid]) \(value[mid...])"
    }
}

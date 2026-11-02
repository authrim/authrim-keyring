import CryptoKit
import Foundation

/// RFC 6238 time-based one-time passwords built on the RFC 4226 HOTP truncation,
/// plus counter-based ones and Steam Guard codes.
nonisolated enum TOTPGenerator {
    /// The characters Steam Guard codes are made of.
    private static let steamAlphabet = Array("23456789BCDFGHJKMNPQRTVWXY")

    struct Code: Equatable {
        let value: String
        /// Start of the time step that produced this code.
        let validFrom: Date
        let validUntil: Date

        func secondsRemaining(at date: Date) -> TimeInterval {
            max(0, validUntil.timeIntervalSince(date))
        }
    }

    /// The code at `date`, or nil for a counter-based account, whose code comes
    /// from `AccountStore.nextCode(for:)` instead.
    static func code(for account: OTPAccount, at date: Date = .now) -> Code? {
        switch account.kind {
        case .totp:
            code(secret: account.secret, algorithm: account.algorithm, digits: account.digits, period: account.period, at: date)
        case .steam:
            timeStep(period: account.period, at: date) { steam(secret: account.secret, counter: $0) }
        case .hotp:
            nil
        }
    }

    static func code(secret: Data, algorithm: OTPAlgorithm, digits: Int, period: Int, at date: Date) -> Code {
        timeStep(period: period, at: date) { hotp(secret: secret, counter: $0, algorithm: algorithm, digits: digits) }
    }

    private static func timeStep(period: Int, at date: Date, value: (UInt64) -> String) -> Code {
        let period = max(period, 1)
        let seconds = max(0, date.timeIntervalSince1970)
        let counter = UInt64(seconds) / UInt64(period)
        let start = Date(timeIntervalSince1970: TimeInterval(counter * UInt64(period)))
        return Code(value: value(counter), validFrom: start, validUntil: start.addingTimeInterval(TimeInterval(period)))
    }

    static func hotp(secret: Data, counter: UInt64, algorithm: OTPAlgorithm, digits: Int) -> String {
        var modulus: UInt32 = 1
        for _ in 0..<digits { modulus *= 10 }
        let value = truncated(secret: secret, counter: counter, algorithm: algorithm) % modulus
        let text = String(value)
        return String(repeating: "0", count: max(0, digits - text.count)) + text
    }

    /// Steam's variant: the same truncation, spelled out in its alphabet.
    static func steam(secret: Data, counter: UInt64) -> String {
        var value = truncated(secret: secret, counter: counter, algorithm: .sha1)
        var code = ""
        for _ in 0..<OTPAccount.steamDigits {
            code.append(steamAlphabet[Int(value % UInt32(steamAlphabet.count))])
            value /= UInt32(steamAlphabet.count)
        }
        return code
    }

    /// RFC 4226 dynamic truncation of the HMAC of `counter`.
    private static func truncated(secret: Data, counter: UInt64, algorithm: OTPAlgorithm) -> UInt32 {
        let message = withUnsafeBytes(of: counter.bigEndian) { Data($0) }
        let key = SymmetricKey(data: secret)
        let mac: [UInt8] = switch algorithm {
        case .sha1: Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
        case .sha256: Array(HMAC<SHA256>.authenticationCode(for: message, using: key))
        case .sha512: Array(HMAC<SHA512>.authenticationCode(for: message, using: key))
        }

        let offset = Int(mac[mac.count - 1] & 0x0F)
        return (UInt32(mac[offset] & 0x7F) << 24)
            | (UInt32(mac[offset + 1]) << 16)
            | (UInt32(mac[offset + 2]) << 8)
            | UInt32(mac[offset + 3])
    }

    /// Splits a code into two halves for readability, e.g. "123 456".
    static func formatted(_ value: String) -> String {
        guard value.count >= 6 else { return value }
        let mid = value.index(value.startIndex, offsetBy: value.count / 2)
        return "\(value[..<mid]) \(value[mid...])"
    }
}

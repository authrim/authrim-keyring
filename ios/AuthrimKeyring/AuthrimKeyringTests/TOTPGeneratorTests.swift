import Foundation
import Testing
@testable import AuthrimKeyring

struct TOTPGeneratorTests {
    private static let rfcSecret = Data("12345678901234567890".utf8)

    /// RFC 4226 appendix D.
    @Test(arguments: zip(0..<10, ["755224", "287082", "359152", "969429", "338314",
                                  "254676", "287922", "162583", "399871", "520489"]))
    func rfc4226(counter: Int, expected: String) {
        let code = TOTPGenerator.hotp(secret: Self.rfcSecret, counter: UInt64(counter), algorithm: .sha1, digits: 6)
        #expect(code == expected)
    }

    /// RFC 6238 appendix B, with the key lengths the RFC uses for each algorithm.
    @Test(arguments: [
        (OTPAlgorithm.sha1, "12345678901234567890", 59.0, "94287082"),
        (.sha256, "12345678901234567890123456789012", 59.0, "46119246"),
        (.sha512, "1234567890123456789012345678901234567890123456789012345678901234", 59.0, "90693936"),
        (.sha1, "12345678901234567890", 1_111_111_109.0, "07081804"),
        (.sha256, "12345678901234567890123456789012", 1_111_111_109.0, "68084774"),
        (.sha512, "1234567890123456789012345678901234567890123456789012345678901234", 1_111_111_109.0, "25091201"),
    ])
    func rfc6238(algorithm: OTPAlgorithm, key: String, time: TimeInterval, expected: String) {
        let code = TOTPGenerator.code(secret: Data(key.utf8), algorithm: algorithm, digits: 8, period: 30, at: Date(timeIntervalSince1970: time))
        #expect(code.value == expected)
    }

    @Test func steamCodes() throws {
        let secret = try #require(Base32.decode("JBSWY3DPEHPK3PXP"))
        let account = OTPAccount(issuer: "Steam", accountName: "player", secret: secret, kind: .steam)
        #expect(TOTPGenerator.code(for: account, at: Date(timeIntervalSince1970: 0))?.value == "VH8YJ")
        #expect(TOTPGenerator.code(for: account, at: Date(timeIntervalSince1970: 1_700_000_000))?.value == "2KM2P")
    }

    @Test func counterBasedAccountsHaveNoTimedCode() {
        let account = OTPAccount(issuer: "Bank", accountName: "", secret: Self.rfcSecret, kind: .hotp(counter: 3))
        #expect(TOTPGenerator.code(for: account) == nil)
    }

    @Test func periodOtherThanThirtySeconds() {
        let code = TOTPGenerator.code(secret: Self.rfcSecret, algorithm: .sha1, digits: 6, period: 15, at: Date(timeIntervalSince1970: 100))
        #expect(code.validFrom == Date(timeIntervalSince1970: 90))
        #expect(code.validUntil == Date(timeIntervalSince1970: 105))
    }
}

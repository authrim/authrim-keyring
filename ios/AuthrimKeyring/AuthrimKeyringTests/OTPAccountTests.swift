import Foundation
import Testing
@testable import AuthrimKeyring

struct OTPAuthURITests {
    @Test func timeBased() throws {
        let account = try OTPAuthURI.parse("otpauth://totp/Example:alex@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&period=60&digits=8&algorithm=SHA256")
        #expect(account.kind == .totp)
        #expect(account.issuer == "Example")
        #expect(account.accountName == "alex@example.com")
        #expect(account.period == 60)
        #expect(account.digits == 8)
        #expect(account.algorithm == .sha256)
    }

    @Test func counterBased() throws {
        let account = try OTPAuthURI.parse("otpauth://hotp/Bank:alex?secret=JBSWY3DPEHPK3PXP&counter=42")
        #expect(account.kind == .hotp(counter: 42))
    }

    @Test func counterBasedWithoutCounterStartsAtZero() throws {
        #expect(try OTPAuthURI.parse("otpauth://hotp/Bank:alex?secret=JBSWY3DPEHPK3PXP").kind == .hotp(counter: 0))
    }

    @Test func invalidCounter() {
        #expect(throws: OTPAuthURI.ParseError.invalidCounter("-1")) {
            try OTPAuthURI.parse("otpauth://hotp/Bank:alex?secret=JBSWY3DPEHPK3PXP&counter=-1")
        }
    }

    @Test(arguments: [
        "otpauth://steam/Steam:player?secret=JBSWY3DPEHPK3PXP",
        "otpauth://totp/Steam:player?secret=JBSWY3DPEHPK3PXP&encoder=steam&digits=5",
    ])
    func steam(uri: String) throws {
        let account = try OTPAuthURI.parse(uri)
        #expect(account.kind == .steam)
        #expect(account.digits == 5)
        #expect(account.isSupported)
    }

    @Test(arguments: ["15", "300"])
    func supportedPeriods(period: String) throws {
        #expect(try OTPAuthURI.parse("otpauth://totp/A?secret=JBSWY3DPEHPK3PXP&period=\(period)").period == Int(period))
    }

    @Test(arguments: ["5", "301", "abc"])
    func unsupportedPeriods(period: String) {
        #expect(throws: OTPAuthURI.ParseError.unsupportedPeriod(period)) {
            try OTPAuthURI.parse("otpauth://totp/A?secret=JBSWY3DPEHPK3PXP&period=\(period)")
        }
    }

    @Test func unknownType() {
        #expect(throws: OTPAuthURI.ParseError.unsupportedType("MOTP")) {
            try OTPAuthURI.parse("otpauth://motp/A?secret=JBSWY3DPEHPK3PXP")
        }
    }
}

struct OTPAccountCodingTests {
    private let secret = Data([1, 2, 3, 4, 5])

    @Test func timeBasedKeepsTheVersion1Format() throws {
        let account = OTPAccount(issuer: "Example", accountName: "alex", secret: secret)
        let json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(account)) as? [String: Any]
        let keys = Set(json?.keys.map { $0 } ?? [])
        #expect(keys == ["id", "issuer", "accountName", "secret", "algorithm", "digits", "period", "createdAt"])
    }

    @Test(arguments: [OTPKind.totp, .hotp(counter: 7), .steam])
    func roundTrip(kind: OTPKind) throws {
        let account = OTPAccount(issuer: "Example", accountName: "alex", secret: secret, kind: kind)
        let decoded = try JSONDecoder().decode(OTPAccount.self, from: JSONEncoder().encode(account))
        #expect(decoded == account)
    }

    @Test func readsWhatVersion1Wrote() throws {
        let json = #"{"id":"7B1F5D8E-2C55-4F44-9C1A-3D2B8A9E6F01","issuer":"Example","accountName":"alex","secret":"AQIDBAU=","algorithm":"SHA1","digits":6,"period":30,"createdAt":0}"#
        let account = try JSONDecoder().decode(OTPAccount.self, from: Data(json.utf8))
        #expect(account.kind == .totp)
        #expect(account.isReadableByVersion1)
    }

    @Test func unknownKindIsNotReadAsTimeBased() {
        let json = #"{"id":"7B1F5D8E-2C55-4F44-9C1A-3D2B8A9E6F01","issuer":"Example","accountName":"alex","secret":"AQIDBAU=","algorithm":"SHA1","digits":6,"period":30,"createdAt":0,"kind":"future"}"#
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(OTPAccount.self, from: Data(json.utf8))
        }
    }

    @Test func sameKeyWithDifferentCountersIsOneAccount() {
        let used = OTPAccount(issuer: "Bank", accountName: "", secret: secret, kind: .hotp(counter: 9))
        let fresh = OTPAccount(issuer: "Bank", accountName: "", secret: secret, kind: .hotp(counter: 0))
        #expect(used.generatesSameCodes(as: fresh))
        #expect(!used.generatesSameCodes(as: OTPAccount(issuer: "Bank", accountName: "", secret: secret)))
    }

    @Test func laterCounterWins() {
        #expect(AccountStore.later(.hotp(counter: 3), .hotp(counter: 5)) == .hotp(counter: 5))
        #expect(AccountStore.later(.hotp(counter: 6), .hotp(counter: 5)) == .hotp(counter: 6))
        #expect(AccountStore.later(.totp, .totp) == .totp)
    }

    @Test func version1CompatibilityIsOnlyForWhatItReads() {
        #expect(!OTPAccount(issuer: "A", accountName: "", secret: secret, period: 15).isReadableByVersion1)
        #expect(!OTPAccount(issuer: "A", accountName: "", secret: secret, kind: .steam).isReadableByVersion1)
        #expect(OTPAccount(issuer: "A", accountName: "", secret: secret, period: 60).isReadableByVersion1)
    }
}

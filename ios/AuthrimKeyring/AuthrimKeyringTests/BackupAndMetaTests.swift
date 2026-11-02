import Foundation
import Testing
@testable import AuthrimKeyring

struct EncryptedBackupTests {
    private let password = "correct horse battery"
    private let secret = Data([9, 8, 7, 6, 5, 4, 3, 2, 1, 0])
    /// Whole seconds, as backups keep dates in ISO 8601.
    private let created = Date(timeIntervalSince1970: 1_800_000_000)

    private func version(of file: Data) throws -> Int {
        let object = try JSONSerialization.jsonObject(with: file) as? [String: Any]
        return try #require(object?["version"] as? Int)
    }

    @Test func timeBasedOnlyStaysVersion1() throws {
        let account = OTPAccount(issuer: "Northwind", accountName: "alex", secret: secret, createdAt: created)
        let note = ItemMeta(id: account.id, isFavorite: true, tags: ["Work"])
        let file = try EncryptedBackup.seal(.init(accounts: [account], meta: [note]), password: password)
        #expect(try version(of: file) == 1)
        let opened = try EncryptedBackup.open(file, password: password)
        #expect(opened.accounts == [account])
        #expect(opened.meta == [note])
    }

    @Test(arguments: [OTPKind.hotp(counter: 4), .steam])
    func otherKindsMakeVersion2(kind: OTPKind) throws {
        let account = OTPAccount(issuer: "Harbor", accountName: "alex", secret: secret, createdAt: created, kind: kind)
        let file = try EncryptedBackup.seal(.init(accounts: [account]), password: password)
        #expect(try version(of: file) == 2)
        #expect(try EncryptedBackup.open(file, password: password).accounts == [account])
    }

    @Test func unusualPeriodMakesVersion2() throws {
        let account = OTPAccount(issuer: "Acme", accountName: "", secret: secret, period: 15)
        #expect(try version(of: EncryptedBackup.seal(.init(accounts: [account]), password: password)) == 2)
    }

    @Test func metaForOtherCardsIsLeftOut() throws {
        let account = OTPAccount(issuer: "Northwind", accountName: "alex", secret: secret)
        let file = try EncryptedBackup.seal(.init(accounts: [account], meta: [ItemMeta(id: UUID(), isFavorite: true)]), password: password)
        #expect(try EncryptedBackup.open(file, password: password).meta.isEmpty)
    }
}

struct ItemMetaTests {
    @Test func tagsAreCleaned() {
        #expect(ItemMeta.cleaned([" Work ", "work", "", "Home"]) == ["Work", "Home"])
        #expect(ItemMeta.tag(from: String(repeating: "x", count: 40))?.count == ItemMeta.maximumTagLength)
        #expect(ItemMeta.cleaned((0..<30).map { "t\($0)" }).count == ItemMeta.maximumTags)
    }

    @Test func merging() {
        let id = UUID()
        let merged = ItemMeta(id: id, tags: ["Work"]).merging(ItemMeta(id: UUID(), isFavorite: true, tags: ["work", "Bank"]))
        #expect(merged == ItemMeta(id: id, isFavorite: true, tags: ["Work", "Bank"]))
    }

    @Test func readsWhatItDoesNotFullyKnow() throws {
        let json = #"{"id":"7B1F5D8E-2C55-4F44-9C1A-3D2B8A9E6F01","later":1}"#
        let meta = try JSONDecoder().decode(ItemMeta.self, from: Data(json.utf8))
        #expect(meta.isEmpty)
    }

    @Test func homeFilterRawValues() {
        for filter in [HomeFilter.all, .favorites, .tag("Work: Team")] {
            #expect(HomeFilter(rawValue: filter.rawValue) == filter)
        }
    }

    @Test func searchFindsWebsitesAndTags() {
        let item = KeyringItem.account(OTPAccount(issuer: "Northwind", accountName: "alex", secret: Data([1])))
        #expect(item.matches("north"))
        #expect(item.matches("mail.example", websites: ["mail.example"]))
        #expect(item.matches("work", tags: ["Work"]))
        #expect(!item.matches("bank", websites: ["mail.example"], tags: ["Work"]))
    }
}

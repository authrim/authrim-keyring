import AuthenticationServices
import CryptoKit
import Foundation
import Testing
@testable import AuthrimKeyring

/// The test target runs on iOS 26 or later, where credential exchange exists.
struct CredentialExchangeTests {
    private let secret = Data([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])

    private func passkey(deviceOnly: Bool = false) -> Passkey {
        Passkey(
            id: UUID(),
            credentialID: Data(repeating: 7, count: 16),
            relyingParty: "juniper.example",
            userName: "alex@example.com",
            userHandle: Data("alex".utf8),
            createdAt: Date(timeIntervalSince1970: 1_800_000_000),
            isBackupEligible: !deviceOnly,
            isInSecureEnclave: false,
            privateKey: P256.Signing.PrivateKey().rawRepresentation,
            customTitle: "Juniper Travel"
        )
    }

    @Test func roundTrip() throws {
        let account = OTPAccount(issuer: "Northwind", accountName: "alex", secret: secret, algorithm: .sha256, digits: 8, period: 60)
        let key = passkey()
        let export = CredentialExchange.export(
            accounts: [account, OTPAccount(issuer: "Harbor", accountName: "", secret: secret, kind: .hotp(counter: 2))],
            passkeys: [key, passkey(deviceOnly: true)],
            details: [account.id: AccountDetails(id: account.id, websites: ["northwind.example"], recoveryCodes: [RecoveryCode(code: "abcd-efgh")])],
            meta: [account.id: ItemMeta(id: account.id, isFavorite: true, tags: ["Work"])],
            formatVersion: .v1
        )
        #expect(export.exportedCount == 2)
        #expect(export.leftOutCount == 2)

        // Through JSON, as the system carries it between apps.
        let data = try JSONDecoder().decode(ASExportedCredentialData.self, from: JSONEncoder().encode(export.data))
        let imported = try CredentialExchange.read(data, isDeviceOnly: { _ in false })
        let restored = try #require(imported.accounts.first)
        #expect(imported.accounts.count == 1)
        #expect(restored.generatesSameCodes(as: account))
        #expect(restored.issuer == "Northwind")
        #expect(restored.accountName == "alex")
        let extra = try #require(imported.details.first)
        #expect(extra.id == restored.id)
        #expect(extra.websites == ["northwind.example"])
        #expect(extra.recoveryCodes.map(\.code) == ["abcd-efgh"])

        let restoredKey = try #require(imported.passkeys.first)
        #expect(imported.passkeys.count == 1)
        #expect(restoredKey.privateKey == key.privateKey)
        #expect(restoredKey.credentialID == key.credentialID)
        #expect(restoredKey.relyingParty == key.relyingParty)
        #expect(restoredKey.userHandle == key.userHandle)
        #expect(restoredKey.customTitle == "Juniper Travel")
        #expect(restoredKey.isBackupEligible)

        #expect(imported.meta.contains(ItemMeta(id: restored.id, isFavorite: true, tags: ["Work"])))
        #expect(imported.otherCount == 0)
    }

    @Test func sitesKeptOnThisDeviceStayThere() throws {
        let export = CredentialExchange.export(accounts: [], passkeys: [passkey()], details: [:], meta: [:], formatVersion: .v1)
        let imported = try CredentialExchange.read(export.data, isDeviceOnly: { $0 == "juniper.example" })
        #expect(imported.passkeys.first?.isBackupEligible == false)
    }

    @Test func passwordsAreOnlyCounted() throws {
        let item = ASImportableItem(
            id: Data([1]),
            created: .now,
            lastModified: .now,
            title: "Mail",
            credentials: [.basicAuthentication(.init(
                userName: .init(id: nil, fieldType: .string, value: "alex"),
                password: .init(id: nil, fieldType: .concealedString, value: "not-a-real-password")
            ))]
        )
        let data = ASExportedCredentialData(
            accounts: [ASImportableAccount(id: Data([2]), userName: "", email: "", collections: [], items: [item])],
            formatVersion: .v1,
            exporterRelyingPartyIdentifier: "example.com",
            exporterDisplayName: "Example",
            timestamp: .now
        )
        let imported = try CredentialExchange.read(data)
        #expect(imported.isEmpty)
        #expect(imported.otherCount == 1)
    }

    @Test func otherNotesAreCounted() throws {
        let item = ASImportableItem(
            id: Data([1]),
            created: .now,
            lastModified: .now,
            title: "Remark",
            credentials: [.note(.init(content: .init(id: nil, fieldType: .string, value: "Gate code 1234")))]
        )
        let data = ASExportedCredentialData(
            accounts: [ASImportableAccount(id: Data([2]), userName: "", email: "", collections: [], items: [item])],
            formatVersion: .v1,
            exporterRelyingPartyIdentifier: "example.com",
            exporterDisplayName: "Example",
            timestamp: .now
        )
        #expect(try CredentialExchange.read(data).otherCount == 1)
    }
}

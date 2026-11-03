import Foundation
import Testing
@testable import AuthrimKeyring

struct IssuerTrustTests {
    private let issuer = URL(string: "https://issuer.example.com")!
    private let other = URL(string: "https://other.example.com")!

    private func credential(_ issuer: URL, confirmedAt: Date? = nil) -> StoredCredential {
        StoredCredential(
            id: UUID(), issuer: issuer, issuerDisplayName: "Example", credentialConfigurationId: "admin",
            vct: "v", credentialName: "Admin", claims: [:], issuedAt: Date(), expiresAt: nil,
            keyTag: "tag", confirmationCode: "ABCD-EFGH", sdJwt: "a.b.c~", confirmedAt: confirmedAt)
    }

    @Test func unconfirmedByDefault() {
        #expect(IssuerTrust.of(issuer, trusted: [], credentials: [credential(issuer), credential(other, confirmedAt: .now)]) == .unconfirmed)
    }

    @Test func earliestConfirmationOfTheSameIssuer() {
        let first = Date(timeIntervalSince1970: 1_000)
        let credentials = [credential(issuer, confirmedAt: Date(timeIntervalSince1970: 2_000)), credential(issuer, confirmedAt: first), credential(issuer)]
        #expect(IssuerTrust.of(issuer, trusted: [], credentials: credentials) == .confirmedByUser(first))
    }

    @Test func anchorOutranksTheUser() {
        let trusted = [TrustedIssuer(issuer: issuer, name: "Example University", anchor: "Example Federation")]
        #expect(IssuerTrust.of(issuer, trusted: trusted, credentials: [credential(issuer, confirmedAt: .now)])
            == .verified(name: "Example University", anchor: "Example Federation"))
        #expect(IssuerTrust.of(other, trusted: trusted, credentials: []) == .unconfirmed)
    }

    @Test func oldCredentialsDecodeAsUnconfirmed() throws {
        var json = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(credential(issuer))) as? [String: Any])
        json.removeValue(forKey: "confirmedAt")
        let decoded = try JSONDecoder().decode(StoredCredential.self, from: JSONSerialization.data(withJSONObject: json))
        #expect(decoded.confirmedAt == nil)
    }

    @MainActor @Test func confirmingSavesAndRaisesTheIssuer() {
        let store = MemoryStore()
        let item = credential(issuer)
        store.items = [item]
        let wallet = WalletModel(issuance: PreviewIssuance(), store: store)
        wallet.load()
        #expect(wallet.confirm(item))
        #expect(store.items.last?.confirmedAt != nil)
        #expect(wallet.credentials.first?.confirmedAt != nil)
        if case .confirmedByUser = wallet.trust(for: issuer) {} else { Issue.record("not confirmed") }
    }

    @MainActor @Test func confirmingACredentialMissingFromAStaleListAddsIt() {
        let store = MemoryStore()
        let item = credential(issuer)
        // Not loaded: as when reading the list failed right after issuance.
        let wallet = WalletModel(issuance: PreviewIssuance(), store: store)
        #expect(wallet.confirm(item))
        #expect(wallet.credentials.map(\.id) == [item.id])
        if case .confirmedByUser = wallet.trust(for: issuer) {} else { Issue.record("not confirmed") }
    }

    @MainActor @Test func failedConfirmationLeavesTheIssuerUnconfirmed() {
        let store = MemoryStore()
        let item = credential(issuer)
        store.items = [item]
        let wallet = WalletModel(issuance: PreviewIssuance(), store: store)
        wallet.load()
        store.failSave = true
        #expect(!wallet.confirm(item))
        #expect(wallet.lastError != nil)
        #expect(wallet.trust(for: issuer) == .unconfirmed)
    }
}

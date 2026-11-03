import Foundation

#if DEBUG
/// Stand-ins for the wallet core, so the screens build and preview without it.
struct PreviewIssuance: CredentialIssuanceService {
    enum Outcome: Sendable {
        case success
        case failure(WalletError)
    }

    var preview: Outcome = .success
    var issue: Outcome = .success
    var delay: Duration = .milliseconds(600)

    func preview(offer: String) async throws -> CredentialOfferPreview {
        try await Task.sleep(for: delay)
        if case .failure(let error) = preview { throw error }
        return .previewSample
    }

    func issue(_ preview: CredentialOfferPreview, transactionCode: String?) async throws -> StoredCredential {
        try await Task.sleep(for: delay)
        if case .failure(let error) = issue { throw error }
        return .previewSample
    }
}

final class PreviewCredentialStore: CredentialStore, @unchecked Sendable {
    private var credentials: [StoredCredential]

    init(credentials: [StoredCredential] = []) {
        self.credentials = credentials
    }

    func loadAll() throws -> [StoredCredential] { credentials }
    func save(_ credential: StoredCredential) throws {
        credentials.removeAll { $0.id == credential.id }
        credentials.append(credential)
    }
    func delete(_ credential: StoredCredential) throws { credentials.removeAll { $0.id == credential.id } }
}

extension WalletModel {
    static func preview(
        credentials: [StoredCredential] = [],
        preview: PreviewIssuance.Outcome = .success,
        issue: PreviewIssuance.Outcome = .success
    ) -> WalletModel {
        let model = WalletModel(
            issuance: PreviewIssuance(preview: preview, issue: issue),
            store: PreviewCredentialStore(credentials: credentials)
        )
        model.load()
        return model
    }
}

extension CredentialOfferPreview {
    static let previewSample = CredentialOfferPreview(
        id: UUID(),
        issuer: URL(string: "https://id.example.com")!,
        issuerDisplayName: "Example Corp",
        credentialConfigurationId: "admin_credential",
        credentialName: "Administrator Credential",
        claimNames: ["Name", "Email", "Role"],
        transactionCode: TransactionCodeRequirement(length: 6, numeric: true, description: "Shown on the Keyring page of the admin console.")
    )
}

extension StoredCredential {
    static let previewSample = StoredCredential(
        id: UUID(),
        issuer: URL(string: "https://id.example.com")!,
        issuerDisplayName: "Example Corp",
        credentialConfigurationId: "admin_credential",
        vct: "https://id.example.com/vct/admin",
        credentialName: "Administrator Credential",
        claims: ["Name": "Hanako Yamada", "Email": "hanako@example.com", "Role": "Tenant admin"],
        issuedAt: .now.addingTimeInterval(-86_400),
        expiresAt: .now.addingTimeInterval(86_400 * 300),
        keyTag: "preview.key",
        confirmationCode: "ABCD-EFGH",
        sdJwt: "preview~"
    )

    static let previewExpired = StoredCredential(
        id: UUID(),
        issuer: URL(string: "https://id.example.org:8443")!,
        issuerDisplayName: nil,
        credentialConfigurationId: "admin_credential",
        vct: "https://id.example.org/vct/admin",
        credentialName: "Administrator Credential",
        claims: ["name": "Taro Suzuki"],
        issuedAt: .now.addingTimeInterval(-86_400 * 400),
        expiresAt: .now.addingTimeInterval(-86_400),
        keyTag: "preview.key2",
        confirmationCode: "JKLM-2345",
        sdJwt: "preview~"
    )
}
#endif

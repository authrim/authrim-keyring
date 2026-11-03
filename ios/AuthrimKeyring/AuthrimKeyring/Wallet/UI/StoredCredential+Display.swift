import Foundation

extension StoredCredential {
    var isExpired: Bool {
        guard let expiresAt else { return false }
        return expiresAt <= .now
    }

    /// Claims in a stable order for the detail view.
    var sortedClaims: [(name: String, value: String)] {
        claims.sorted { $0.key.localizedStandardCompare($1.key) == .orderedAscending }
            .map { (name: $0.key, value: $0.value) }
    }

    /// The name and email, when the credential has them, for the one-line summary on a card.
    var summary: String? {
        let wanted = ["name", "email"]
        let values = wanted.compactMap { key in
            claims.first { $0.key.lowercased() == key }?.value
        }
        return values.isEmpty ? nil : values.joined(separator: " · ")
    }

    /// Whether a home search matches this credential.
    func matches(search: String) -> Bool {
        let text = search.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return true }
        return ([credentialName, issuer.walletHost, issuerDisplayName ?? ""] + claims.values)
            .contains { $0.localizedStandardContains(text) }
    }
}

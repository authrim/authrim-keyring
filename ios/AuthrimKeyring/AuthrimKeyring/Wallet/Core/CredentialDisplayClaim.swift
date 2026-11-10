import Foundation

/// A localized label and a verified claim value, snapped at issuance for offline display.
nonisolated struct CredentialDisplayClaim: Codable, Hashable, Identifiable, Sendable {
    let id: String
    let label: String
    let value: String
    let description: String?
    let direction: CredentialTextDirection
}

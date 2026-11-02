import Foundation

/// One card on the home screen: a two-factor account or a passkey.
nonisolated enum KeyringItem: Identifiable, Hashable, Sendable {
    case account(OTPAccount)
    case passkey(Passkey)

    var id: UUID {
        switch self {
        case .account(let account): account.id
        case .passkey(let passkey): passkey.id
        }
    }

    var createdAt: Date {
        switch self {
        case .account(let account): account.createdAt
        case .passkey(let passkey): passkey.createdAt
        }
    }

    var displayTitle: String {
        switch self {
        case .account(let account): account.displayTitle
        case .passkey(let passkey): passkey.displayTitle
        }
    }

    var displaySubtitle: String? {
        switch self {
        case .account(let account): account.displaySubtitle
        case .passkey(let passkey): passkey.displaySubtitle
        }
    }

    /// Whether a search typed on the home screen finds this card, by its names,
    /// the websites set for it, or its tags.
    func matches(_ query: String, websites: [String] = [], tags: [String] = []) -> Bool {
        let names = switch self {
        case .account(let account): [account.issuer, account.accountName]
        case .passkey(let passkey): [passkey.displayTitle, passkey.relyingParty, passkey.userName]
        }
        return (names + websites + tags).contains { $0.localizedCaseInsensitiveContains(query) }
    }
}

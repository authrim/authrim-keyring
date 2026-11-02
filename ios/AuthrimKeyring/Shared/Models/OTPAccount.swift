import Foundation

nonisolated enum OTPAlgorithm: String, Codable, CaseIterable, Identifiable, Sendable {
    case sha1 = "SHA1"
    case sha256 = "SHA256"
    case sha512 = "SHA512"

    var id: String { rawValue }
}

/// A TOTP credential registered by the user.
///
/// TOTP accounts are deliberately independent of tenant memberships: importing a
/// QR code never implies that the user belongs to an organization.
nonisolated struct OTPAccount: Codable, Identifiable, Hashable, Sendable {
    static let supportedDigits = [6, 7, 8]
    static let supportedPeriods = [30, 60]

    var id: UUID
    var issuer: String
    var accountName: String
    var secret: Data
    var algorithm: OTPAlgorithm
    var digits: Int
    var period: Int
    var createdAt: Date
    /// Card face color; nil means a color derived from the name.
    var cardColor: CardColor?

    init(
        id: UUID = UUID(),
        issuer: String,
        accountName: String,
        secret: Data,
        algorithm: OTPAlgorithm = .sha1,
        digits: Int = 6,
        period: Int = 30,
        createdAt: Date = .now,
        cardColor: CardColor? = nil
    ) {
        self.id = id
        self.issuer = issuer
        self.accountName = accountName
        self.secret = secret
        self.algorithm = algorithm
        self.digits = digits
        self.period = period
        self.createdAt = createdAt
        self.cardColor = cardColor
    }

    /// Title shown in lists; falls back to the account name when no issuer was given.
    var displayTitle: String {
        issuer.isEmpty ? accountName : issuer
    }

    /// The color actually shown on the card.
    var effectiveCardColor: CardColor {
        cardColor ?? .automatic(for: displayTitle)
    }

    var displaySubtitle: String? {
        issuer.isEmpty || accountName.isEmpty ? nil : accountName
    }

    /// True when both accounts produce the same codes.
    func generatesSameCodes(as other: OTPAccount) -> Bool {
        secret == other.secret
            && algorithm == other.algorithm
            && digits == other.digits
            && period == other.period
    }

    /// Whether the parameters are ones this app can generate codes for.
    var isSupported: Bool {
        !secret.isEmpty
            && Self.supportedDigits.contains(digits)
            && Self.supportedPeriods.contains(period)
    }
}

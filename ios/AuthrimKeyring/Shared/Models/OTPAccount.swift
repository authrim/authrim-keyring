import Foundation

nonisolated enum OTPAlgorithm: String, Codable, CaseIterable, Identifiable, Sendable {
    case sha1 = "SHA1"
    case sha256 = "SHA256"
    case sha512 = "SHA512"

    var id: String { rawValue }
}

/// How an account's codes are generated.
nonisolated enum OTPKind: Hashable, Sendable {
    /// Time-based (RFC 6238), what nearly every service uses.
    case totp
    /// Counter-based (RFC 4226). `counter` is the one the next code uses.
    case hotp(counter: UInt64)
    /// Steam Guard: time-based, five characters from Steam's own alphabet.
    case steam

    var isTimeBased: Bool {
        if case .hotp = self { false } else { true }
    }

    /// The name shown with the card's details.
    var name: String {
        switch self {
        case .totp: "TOTP"
        case .hotp: "HOTP"
        case .steam: "Steam"
        }
    }
}

/// A one-time code credential registered by the user.
///
/// Accounts are deliberately independent of tenant memberships: importing a
/// QR code never implies that the user belongs to an organization.
nonisolated struct OTPAccount: Codable, Identifiable, Hashable, Sendable {
    static let supportedDigits = [6, 7, 8]
    /// Periods offered when entering a key by hand.
    static let commonPeriods = [30, 60]
    /// Periods accepted from setup codes and other apps, in seconds.
    static let supportedPeriods = 10...300
    static let steamDigits = 5

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
    var kind: OTPKind

    init(
        id: UUID = UUID(),
        issuer: String,
        accountName: String,
        secret: Data,
        algorithm: OTPAlgorithm = .sha1,
        digits: Int = 6,
        period: Int = 30,
        createdAt: Date = .now,
        cardColor: CardColor? = nil,
        kind: OTPKind = .totp
    ) {
        self.id = id
        self.issuer = issuer
        self.accountName = accountName
        self.secret = secret
        self.createdAt = createdAt
        self.cardColor = cardColor
        self.kind = kind
        // Steam fixes its parameters; any others given are meaningless.
        self.algorithm = kind == .steam ? .sha1 : algorithm
        self.digits = kind == .steam ? Self.steamDigits : digits
        self.period = kind == .steam ? 30 : period
    }

    private enum CodingKeys: String, CodingKey {
        case id, issuer, accountName, secret, algorithm, digits, period, createdAt, cardColor
        case kind, counter
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        issuer = try container.decode(String.self, forKey: .issuer)
        accountName = try container.decode(String.self, forKey: .accountName)
        secret = try container.decode(Data.self, forKey: .secret)
        algorithm = try container.decode(OTPAlgorithm.self, forKey: .algorithm)
        digits = try container.decode(Int.self, forKey: .digits)
        period = try container.decode(Int.self, forKey: .period)
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        cardColor = try container.decodeIfPresent(CardColor.self, forKey: .cardColor)
        // Absent in what versions 1.0 and 1.1 wrote, which are all time-based. A kind
        // added later fails here, rather than showing wrong codes as time-based.
        switch try container.decodeIfPresent(String.self, forKey: .kind) {
        case nil, "totp":
            kind = .totp
        case "hotp":
            kind = .hotp(counter: try container.decode(UInt64.self, forKey: .counter))
        case "steam":
            kind = .steam
        case let other?:
            throw DecodingError.dataCorruptedError(forKey: .kind, in: container, debugDescription: "Unknown kind \(other)")
        }
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(issuer, forKey: .issuer)
        try container.encode(accountName, forKey: .accountName)
        try container.encode(secret, forKey: .secret)
        try container.encode(algorithm, forKey: .algorithm)
        try container.encode(digits, forKey: .digits)
        try container.encode(period, forKey: .period)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encodeIfPresent(cardColor, forKey: .cardColor)
        // Time-based accounts keep exactly the format earlier versions wrote.
        switch kind {
        case .totp:
            break
        case .hotp(let counter):
            try container.encode("hotp", forKey: .kind)
            try container.encode(counter, forKey: .counter)
        case .steam:
            try container.encode("steam", forKey: .kind)
        }
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

    /// True when both accounts produce the same codes. Counter-based accounts with
    /// the same key count as the same whatever their counters, which only advance.
    func generatesSameCodes(as other: OTPAccount) -> Bool {
        guard secret == other.secret, algorithm == other.algorithm, digits == other.digits else { return false }
        switch (kind, other.kind) {
        case (.totp, .totp): return period == other.period
        case (.hotp, .hotp), (.steam, .steam): return true
        default: return false
        }
    }

    /// Whether the parameters are ones this app can generate codes for.
    var isSupported: Bool {
        guard !secret.isEmpty else { return false }
        switch kind {
        case .totp: return Self.supportedDigits.contains(digits) && Self.supportedPeriods.contains(period)
        case .hotp: return Self.supportedDigits.contains(digits)
        case .steam: return true
        }
    }

    /// Whether versions 1.0 and 1.1 handle this account correctly. They know only
    /// time-based codes, and accept only these periods when restoring a backup.
    var isReadableByVersion1: Bool {
        kind == .totp && Self.supportedDigits.contains(digits) && Self.commonPeriods.contains(period)
    }
}

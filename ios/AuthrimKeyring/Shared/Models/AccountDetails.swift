import Foundation

/// A single-use code a service hands out for signing in without the authenticator.
nonisolated struct RecoveryCode: Codable, Hashable, Identifiable, Sendable {
    var id = UUID()
    var code: String
    /// When the user marked it as used; nil while it can still be used.
    var usedAt: Date?

    var isUsed: Bool { usedAt != nil }
}

/// What a card holds besides its key, stored as its own Keychain item.
///
/// Kept apart from `OTPAccount` because version 1.0 rewrites an account with only
/// the fields it knows, which would drop these on a device that has not updated.
nonisolated struct AccountDetails: Codable, Hashable, Identifiable, Sendable {
    static let maximumRecoveryCodes = 100
    static let maximumRecoveryCodeLength = 64

    /// The account these details belong to.
    var id: UUID
    /// Domains where the codes are offered by AutoFill, such as `example.com`.
    var websites: [String] = []
    var recoveryCodes: [RecoveryCode] = []

    init(id: UUID, websites: [String] = [], recoveryCodes: [RecoveryCode] = []) {
        self.id = id
        self.websites = websites
        self.recoveryCodes = recoveryCodes
    }

    // A later version may add fields; an older item may lack some.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        websites = try container.decodeIfPresent([String].self, forKey: .websites) ?? []
        recoveryCodes = try container.decodeIfPresent([RecoveryCode].self, forKey: .recoveryCodes) ?? []
    }

    var isEmpty: Bool { websites.isEmpty && recoveryCodes.isEmpty }

    var unusedRecoveryCodeCount: Int {
        recoveryCodes.count { !$0.isUsed }
    }

    /// Combines details of the same account kept in two places. Entries here stay
    /// first; a code used in either place counts as used. Nothing is dropped, even
    /// past the limit for codes added by hand.
    func merging(_ other: AccountDetails) -> AccountDetails {
        var result = self
        for site in other.websites where !result.websites.contains(site) {
            result.websites.append(site)
        }
        for code in other.recoveryCodes {
            if let index = result.recoveryCodes.firstIndex(where: { $0.code == code.code }) {
                if result.recoveryCodes[index].usedAt == nil {
                    result.recoveryCodes[index].usedAt = code.usedAt
                }
            } else {
                result.recoveryCodes.append(code)
            }
        }
        return result
    }

    /// Adds the codes in `text`, skipping ones already here. Returns how many were added.
    @discardableResult
    mutating func addRecoveryCodes(from text: String) -> Int {
        var known = Set(recoveryCodes.map(\.code))
        var added = 0
        for code in Self.recoveryCodes(in: text) where recoveryCodes.count < Self.maximumRecoveryCodes {
            guard known.insert(code).inserted else { continue }
            recoveryCodes.append(RecoveryCode(code: code))
            added += 1
        }
        return added
    }

    /// Splits pasted text into codes. Services list them one per line, in columns, or
    /// separated by commas. A single space stays inside a code, as in `1234 5678`;
    /// bullets and list numbering such as `1.` or `2)` are dropped.
    static func recoveryCodes(in text: String) -> [String] {
        text.components(separatedBy: CharacterSet.newlines.union(CharacterSet(charactersIn: ",;")))
            .flatMap { line in
                line.replacing(/\t|\s{2,}/, with: "\n").split(separator: "\n")
            }
            .map { token in
                token
                    .trimmingCharacters(in: .whitespaces)
                    .replacing(/^(?:[•·*\-–]|\d{1,3}[.)])\s+/, with: "")
                    // A sentence-ending period, as the keyboard adds after a double space.
                    .trimmingCharacters(in: CharacterSet.whitespaces.union(CharacterSet(charactersIn: ".")))
            }
            // List numbering separated from its code by a tab, such as "1.\tABCD-EFGH".
            .filter { !$0.isEmpty && $0.count <= maximumRecoveryCodeLength && $0.wholeMatch(of: /\d{1,3}\)?/) == nil }
    }
}

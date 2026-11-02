import Foundation

/// How the user has organized a card, an account's or a passkey's.
///
/// Kept as a Keychain item of its own, under a service versions 1.0 and 1.1 never
/// read: they rewrite a card's own item with only the fields they know, which
/// would drop these. Decoded field by field, so later versions can add to it.
nonisolated struct ItemMeta: Codable, Hashable, Identifiable, Sendable {
    static let maximumTags = 20
    static let maximumTagLength = 32

    var id: UUID
    var isFavorite = false
    var tags: [String] = []

    init(id: UUID, isFavorite: Bool = false, tags: [String] = []) {
        self.id = id
        self.isFavorite = isFavorite
        self.tags = tags
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        isFavorite = try container.decodeIfPresent(Bool.self, forKey: .isFavorite) ?? false
        tags = try container.decodeIfPresent([String].self, forKey: .tags) ?? []
    }

    var isEmpty: Bool { !isFavorite && tags.isEmpty }

    /// Both together, as when the same card comes from two places.
    func merging(_ other: ItemMeta) -> ItemMeta {
        var result = self
        result.isFavorite = isFavorite || other.isFavorite
        result.tags = Self.cleaned(tags + other.tags)
        return result
    }

    /// A tag as typed, trimmed and shortened; nil when nothing is left.
    static func tag(from text: String) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : String(trimmed.prefix(maximumTagLength))
    }

    /// Tags without repeats, ignoring case, and no more than allowed.
    static func cleaned(_ tags: [String]) -> [String] {
        var result: [String] = []
        for tag in tags.compactMap(tag(from:)) where !result.contains(where: { $0.caseInsensitiveCompare(tag) == .orderedSame }) {
            result.append(tag)
        }
        return Array(result.prefix(maximumTags))
    }
}

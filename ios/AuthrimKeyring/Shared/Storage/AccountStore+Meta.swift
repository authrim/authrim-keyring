import Foundation

/// Favorites and tags.
extension AccountStore {
    func meta(for id: UUID) -> ItemMeta {
        meta[id] ?? ItemMeta(id: id)
    }

    /// Every tag in use, in alphabetical order.
    var allTags: [String] {
        var seen: [String] = []
        for tag in meta.values.flatMap(\.tags) where !seen.contains(where: { $0.caseInsensitiveCompare(tag) == .orderedSame }) {
            seen.append(tag)
        }
        return seen.sorted { $0.localizedStandardCompare($1) == .orderedAscending }
    }

    func setFavorite(_ isFavorite: Bool, for id: UUID) {
        var new = meta(for: id)
        new.isFavorite = isFavorite
        updateMeta(new)
    }

    func setTags(_ tags: [String], for id: UUID) {
        var new = meta(for: id)
        new.tags = ItemMeta.cleaned(tags)
        updateMeta(new)
    }

    /// Both at once, as an edit screen saves them; nothing is written when unchanged.
    func setOrganization(isFavorite: Bool, tags: [String], for id: UUID) {
        var new = meta(for: id)
        new.isFavorite = isFavorite
        new.tags = ItemMeta.cleaned(tags)
        guard new != meta(for: id) else { return }
        updateMeta(new)
    }

    private func updateMeta(_ new: ItemMeta) {
        do {
            try saveMeta(new)
        } catch {
            lastError = error.localizedDescription
        }
    }

    func saveMeta(_ new: ItemMeta) throws {
        // A partial copy must not replace what could not be read.
        guard !isMetaUnavailable else { throw MetaError.unavailable }
        if new.isEmpty {
            try metaKeychain.delete(id: new.id, from: location)
            meta[new.id] = nil
        } else {
            try metaKeychain.save(new, to: location)
            meta[new.id] = new
        }
    }

    /// Goes with the card; a leftover would attach to a new card reusing the identifier.
    func deleteMeta(of id: UUID) {
        try? metaKeychain.delete(id: id, from: location)
        meta[id] = nil
    }

    enum MetaError: LocalizedError {
        case unavailable

        var errorDescription: String? {
            String(localized: "Favorites and tags could not be read from the Keychain. Try again after restarting the app.")
        }
    }
}

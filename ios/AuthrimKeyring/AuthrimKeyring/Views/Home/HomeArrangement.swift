import SwiftUI

/// How the home screen orders the cards. Favorites come first in every order.
enum HomeSort: String, CaseIterable, Identifiable {
    /// The order the user arranged.
    case custom
    case name
    case newest

    var id: String { rawValue }

    var label: LocalizedStringKey {
        switch self {
        case .custom: "Your Order"
        case .name: "By Name"
        case .newest: "Recently Added"
        }
    }
}

/// What swiping sideways on the home screen moves between. Both loop around.
enum HomePaging: String, CaseIterable, Identifiable {
    /// Favorites, then every other card.
    case favorites
    /// Credentials, passkeys, then two-factor codes.
    case kinds

    var id: String { rawValue }

    var label: LocalizedStringKey {
        switch self {
        case .favorites: "Favorites and Others"
        case .kinds: "By Kind"
        }
    }

    var pages: [HomePage] {
        switch self {
        case .favorites: [.favorites, .others]
        case .kinds: [.credentials, .passkeys, .codes]
        }
    }

    /// The page to show: the one last shown (its raw value), or else the first that has cards.
    func page(shown: String, hasCards: (HomePage) -> Bool) -> HomePage {
        if let page = HomePage(rawValue: shown), pages.contains(page) { return page }
        return pages.first(where: hasCards) ?? pages[0]
    }

    /// The page `step` pages along from `page`, wrapping around at either end.
    func page(from page: HomePage, by step: Int) -> HomePage {
        guard let index = pages.firstIndex(of: page) else { return pages[0] }
        let count = pages.count
        return pages[((index + step) % count + count) % count]
    }
}

/// One page of cards on the home screen.
enum HomePage: String, Identifiable {
    case favorites
    case others
    case credentials
    case passkeys
    case codes

    var id: String { rawValue }

    var title: LocalizedStringKey {
        switch self {
        case .favorites: "Favorites"
        case .others: "Others"
        case .credentials: "Credentials"
        case .passkeys: "Passkeys"
        case .codes: "2FA"
        }
    }

    /// Whether wallet credentials, which cannot be favorites, show on this page.
    var showsCredentials: Bool { self == .others || self == .credentials }

    func contains(_ item: KeyringItem, isFavorite: Bool) -> Bool {
        switch (self, item) {
        case (.favorites, _): isFavorite
        case (.others, _): !isFavorite
        case (.passkeys, .passkey), (.codes, .account): true
        default: false
        }
    }
}

extension AccountStore {
    /// The cards the home screen shows, in the order it shows them. Without a page, every card.
    func arrangedItems(search: String, sort: HomeSort, page: HomePage?) -> [KeyringItem] {
        let query = search.trimmingCharacters(in: .whitespaces)
        var result = items.filter { item in
            let note = meta(for: item.id)
            if let page, !page.contains(item, isFavorite: note.isFavorite) { return false }
            return query.isEmpty || item.matches(query, websites: details[item.id]?.websites ?? [], tags: note.tags)
        }
        switch sort {
        case .custom:
            break
        case .name:
            result.sort { $0.displayTitle.localizedStandardCompare($1.displayTitle) == .orderedAscending }
        case .newest:
            result.sort { $0.createdAt > $1.createdAt }
        }
        // Stable, so each group keeps the order chosen above.
        let favorites = result.filter { meta(for: $0.id).isFavorite }
        let others = result.filter { !meta(for: $0.id).isFavorite }
        return favorites + others
    }
}

/// Adds a card to the favorites or takes it out, for a card's menu.
struct FavoriteButton: View {
    @Environment(AccountStore.self) private var store
    let id: UUID

    var body: some View {
        if store.meta(for: id).isFavorite {
            Button("Remove from Favorites", systemImage: "star.slash") { store.setFavorite(false, for: id) }
        } else {
            Button("Add to Favorites", systemImage: "star") { store.setFavorite(true, for: id) }
        }
    }
}

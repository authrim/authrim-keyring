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

/// Which cards the home screen shows.
enum HomeFilter: Hashable, RawRepresentable {
    case all
    case favorites
    case tag(String)

    init?(rawValue: String) {
        switch rawValue {
        case "": self = .all
        case "favorites": self = .favorites
        case let value where value.hasPrefix("tag:"): self = .tag(String(value.dropFirst(4)))
        default: return nil
        }
    }

    var rawValue: String {
        switch self {
        case .all: ""
        case .favorites: "favorites"
        case .tag(let tag): "tag:" + tag
        }
    }
}

extension AccountStore {
    /// The cards the home screen shows, in the order it shows them.
    func arrangedItems(search: String, sort: HomeSort, filter: HomeFilter) -> [KeyringItem] {
        let query = search.trimmingCharacters(in: .whitespaces)
        var result = items.filter { item in
            let note = meta(for: item.id)
            switch filter {
            case .all: break
            case .favorites: guard note.isFavorite else { return false }
            case .tag(let tag): guard note.tags.contains(where: { $0.caseInsensitiveCompare(tag) == .orderedSame }) else { return false }
            }
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

/// The toolbar menu that sorts and filters the cards, and opens manual reordering.
struct HomeArrangeMenu: View {
    @Binding var sort: HomeSort
    @Binding var filter: HomeFilter
    let tags: [String]
    let canReorder: Bool
    let onReorder: () -> Void

    var body: some View {
        Menu {
            Section("Sort By") {
                Picker("Sort By", selection: $sort) {
                    ForEach(HomeSort.allCases) { Text($0.label).tag($0) }
                }
            }
            Section("Show") {
                Picker("Show", selection: $filter) {
                    Label("All Cards", systemImage: "rectangle.stack").tag(HomeFilter.all)
                    Label("Favorites", systemImage: "star").tag(HomeFilter.favorites)
                    ForEach(tags, id: \.self) { tag in
                        Label(tag, systemImage: "tag").tag(HomeFilter.tag(tag))
                    }
                }
            }
            if sort == .custom, canReorder {
                Section {
                    Button("Reorder…", systemImage: "arrow.up.arrow.down", action: onReorder)
                }
            }
        } label: {
            Label("Sort and Filter", systemImage: filter == .all ? "line.3.horizontal.decrease.circle" : "line.3.horizontal.decrease.circle.fill")
        }
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

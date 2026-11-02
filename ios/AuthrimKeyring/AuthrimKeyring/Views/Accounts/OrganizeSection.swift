import SwiftUI

/// Favorite and tags, in a card's edit screen. Saved with the rest of the screen.
struct OrganizeSection: View {
    @Environment(AccountStore.self) private var store
    @Binding var isFavorite: Bool
    @Binding var tags: [String]
    /// Kept by the screen, so a tag typed without pressing Done is saved too.
    @Binding var newTag: String

    /// Tags on other cards, offered with a tap.
    private var suggestions: [String] {
        store.allTags.filter { tag in !tags.contains { $0.caseInsensitiveCompare(tag) == .orderedSame } }
    }

    var body: some View {
        Section {
            Toggle("Favorite", systemImage: "star", isOn: $isFavorite)
            ForEach(tags, id: \.self) { tag in
                Label(tag, systemImage: "tag")
            }
            .onDelete { tags.remove(atOffsets: $0) }
            if tags.count < ItemMeta.maximumTags {
                TextField("Add Tag", text: $newTag)
                    .submitLabel(.done)
                    .onSubmit {
                        tags = Self.adding(newTag, to: tags)
                        newTag = ""
                    }
                if !suggestions.isEmpty {
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack {
                            ForEach(suggestions, id: \.self) { tag in
                                Button(tag, systemImage: "plus") { tags.append(tag) }
                                    .buttonStyle(.bordered)
                                    .buttonBorderShape(.capsule)
                                    .controlSize(.small)
                            }
                        }
                    }
                }
            }
        } header: {
            Text("Organize")
        } footer: {
            Text("Favorites come first on the home screen. Tags let you show only some cards.")
        }
    }

    static func adding(_ typed: String, to tags: [String]) -> [String] {
        guard let tag = ItemMeta.tag(from: typed) else { return tags }
        return ItemMeta.cleaned(tags + [tag])
    }
}

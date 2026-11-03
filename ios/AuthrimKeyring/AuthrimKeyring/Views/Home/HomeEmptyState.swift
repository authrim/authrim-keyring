import SwiftUI

/// What the home screen shows before any card has been added.
struct HomeEmptyState: View {
    @Environment(AccountStore.self) private var store
    @Environment(AppLock.self) private var appLock
    let onAdd: () -> Void

    var body: some View {
        ContentUnavailableView {
            Label("No Accounts", systemImage: "key.horizontal")
        } description: {
            if store.iCloudAccountCount > 0 {
                Text("Accounts were found in iCloud Keychain. Turn on sync to use them on this device.")
            } else {
                Text("Scan the QR code shown when you turn on two-factor authentication for a service.")
            }
        } actions: {
            if store.iCloudAccountCount > 0 {
                Button("Turn On iCloud Sync") { Task { await store.enableSync(confirmingWith: appLock) } }
                    .buttonStyle(.borderedProminent)
                Button("Add Account", action: onAdd)
            } else {
                Button("Add Account", action: onAdd)
                    .buttonStyle(.borderedProminent)
            }
        }
        .readableOverWallpaper()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// What the home screen shows when a search or filter leaves no card.
struct NoMatchingCards: View {
    let search: String
    let filter: HomeFilter
    let onShowAll: () -> Void

    var body: some View {
        Group {
            if !search.trimmingCharacters(in: .whitespaces).isEmpty {
                ContentUnavailableView.search(text: search)
            } else {
                ContentUnavailableView {
                    switch filter {
                    case .tag(let tag): Label("No Cards Tagged “\(tag)”", systemImage: "tag")
                    default: Label("No Favorites", systemImage: "star")
                    }
                } description: {
                    if filter == .favorites {
                        Text("Touch and hold a card to add it to your favorites.")
                    }
                } actions: {
                    Button("Show All Cards", action: onShowAll)
                }
            }
        }
        .readableOverWallpaper()
        .padding(.top, 40)
    }
}

/// Puts frosted glass behind text on the home screen when a wallpaper is shown,
/// so the text reads over any picture.
private struct ReadableOverWallpaper: ViewModifier {
    @Environment(WallpaperStore.self) private var wallpaper
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    func body(content: Content) -> some View {
        if wallpaper.settings.kind == .system {
            content
        } else {
            content
                // Hugs the text, except at the largest sizes, where it may need the whole screen.
                .fixedSize(horizontal: false, vertical: !dynamicTypeSize.isAccessibilitySize)
                .padding(.vertical, 8)
                .background(.regularMaterial, in: .rect(cornerRadius: 24))
                .padding(.horizontal, 24)
        }
    }
}

private extension View {
    func readableOverWallpaper() -> some View {
        modifier(ReadableOverWallpaper())
    }
}

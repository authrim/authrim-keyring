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

/// What the home screen shows when a search or a page has no card.
struct NoMatchingCards: View {
    let search: String
    /// Nil while searching, which covers every page.
    let page: HomePage?

    var body: some View {
        Group {
            if let page {
                ContentUnavailableView {
                    switch page {
                    case .favorites: Label("No Favorites", systemImage: "star")
                    case .others: Label("No Other Cards", systemImage: "rectangle.stack")
                    case .credentials: Label("No Credentials", systemImage: "person.text.rectangle")
                    case .passkeys: Label("No Passkeys", systemImage: "person.badge.key")
                    case .codes: Label("No Two-Factor Codes", systemImage: "key.horizontal")
                    }
                } description: {
                    switch page {
                    case .favorites: Text("Touch and hold a card to add it to your favorites.")
                    case .others: Text("Every card is in your favorites.")
                    case .credentials: Text("Tap + and scan a credential offer to receive one.")
                    case .passkeys: Text("When a website offers to create a passkey, choose Keyring to keep it here.")
                    case .codes: Text("Tap + to add an account.")
                    }
                }
            } else {
                ContentUnavailableView.search(text: search)
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

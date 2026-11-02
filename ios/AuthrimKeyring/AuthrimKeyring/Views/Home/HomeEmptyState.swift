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
        .padding(.top, 40)
    }
}

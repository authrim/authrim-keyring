import SwiftUI

/// What swiping on the home screen moves between, and how the cards are ordered.
struct HomeScreenSettingsView: View {
    @Environment(AccountStore.self) private var store
    @AppStorage("homePaging") private var paging = HomePaging.kinds
    @AppStorage("homeSort") private var sort = HomeSort.custom

    var body: some View {
        Form {
            Section {
                Picker("Swipe Between", selection: $paging) {
                    ForEach(HomePaging.allCases) { Text($0.label).tag($0) }
                }
                .pickerStyle(.inline)
                .labelsHidden()
            } header: {
                Text("Swipe Between")
            } footer: {
                switch paging {
                case .favorites:
                    Text("Swipe left or right on the home screen to switch between your favorites and the other cards.")
                case .kinds:
                    Text("Swipe left or right on the home screen to switch between credentials, passkeys and two-factor codes.")
                }
            }

            Section {
                Picker("Sort By", selection: $sort) {
                    ForEach(HomeSort.allCases) { Text($0.label).tag($0) }
                }
                if sort == .custom, store.items.count > 1 {
                    NavigationLink("Reorder…") { ReorderAccountsView() }
                }
            } footer: {
                Text("Favorites come first in every order.")
            }
        }
        .navigationTitle("Home Screen")
        .navigationBarTitleDisplayMode(.inline)
    }
}

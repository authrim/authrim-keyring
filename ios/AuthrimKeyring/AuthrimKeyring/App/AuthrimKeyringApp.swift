import SwiftUI

@main
struct AuthrimKeyringApp: App {
    @State private var store = AccountStore()
    @State private var appLock = AppLock()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(store)
                .environment(appLock)
                .task { store.load() }
        }
    }
}

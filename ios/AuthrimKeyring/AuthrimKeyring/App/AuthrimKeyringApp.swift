import SwiftUI

@main
struct AuthrimKeyringApp: App {
    @State private var store = AccountStore()
    @State private var appLock = AppLock()

    init() {
        #if DEBUG
        if ScreenshotDemo.isEnabled {
            _store = State(initialValue: ScreenshotDemo.makeStore())
        }
        #endif
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(store)
                .environment(appLock)
                .task { store.load() }
        }
    }
}

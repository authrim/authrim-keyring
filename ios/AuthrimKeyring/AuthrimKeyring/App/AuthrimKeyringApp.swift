import SwiftUI

@main
struct AuthrimKeyringApp: App {
    @State private var store: AccountStore
    @State private var appLock: AppLock
    @State private var wallpaper: WallpaperStore
    @Environment(\.scenePhase) private var scenePhase

    init() {
        // Before the stores read their settings from the App Group.
        SharedDefaults.migrateFromStandard()
        Wordmark.registerFont()
        #if DEBUG
        if ScreenshotDemo.isEnabled {
            _store = State(initialValue: ScreenshotDemo.makeStore())
            _appLock = State(initialValue: ScreenshotDemo.makeAppLock())
            _wallpaper = State(initialValue: ScreenshotDemo.makeWallpaper())
            return
        }
        #endif
        _store = State(initialValue: AccountStore())
        _appLock = State(initialValue: AppLock())
        _wallpaper = State(initialValue: WallpaperStore())
    }

    /// Whether the cards are the screenshots' fictional ones, which must not
    /// replace the AutoFill suggestions of this device.
    private var isScreenshotDemo: Bool {
        #if DEBUG
        ScreenshotDemo.isEnabled
        #else
        false
        #endif
    }

    private struct AutoFillRegistration: Hashable {
        var identities: CredentialIdentitySync.Identities?
        var isActive: Bool
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(store)
                .environment(appLock)
                .environment(wallpaper)
                .task { store.load() }
                // Keeps AutoFill suggestions in step with the cards, including changes
                // that arrive through iCloud. Also runs on each return to the app, in
                // case AutoFill was turned on in Settings meanwhile.
                .task(id: AutoFillRegistration(identities: store.autoFillIdentities, isActive: scenePhase == .active)) {
                    guard scenePhase == .active, !isScreenshotDemo, let identities = store.autoFillIdentities else { return }
                    await CredentialIdentitySync.replace(with: identities)
                }
        }
    }
}

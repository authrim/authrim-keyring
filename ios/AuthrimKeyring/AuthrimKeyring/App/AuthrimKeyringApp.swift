import SwiftUI

@main
struct AuthrimKeyringApp: App {
    @State private var store: AccountStore
    @State private var appLock: AppLock
    @State private var wallpaper: WallpaperStore
    @State private var wallet: WalletModel
    /// The made-up cards shown in place of the user's own while Demo Mode is on.
    @State private var demo: DemoMode.Session?
    @AppStorage(DemoMode.key) private var isDemoModeOn = false
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
            _wallet = State(initialValue: Self.makeWallet())
            return
        }
        #endif
        _store = State(initialValue: AccountStore())
        _appLock = State(initialValue: AppLock())
        _wallpaper = State(initialValue: WallpaperStore())
        _wallet = State(initialValue: Self.makeWallet())
        if UserDefaults.standard.bool(forKey: DemoMode.key) {
            _demo = State(initialValue: DemoMode.Session(fresh: false))
        }
    }

    /// The one place the wallet screens get their real services.
    private static func makeWallet() -> WalletModel {
        let store = KeychainCredentialStore()
        let eudiTestProvider = EUDITestKeyAttestationProvider()
        let eudiTestWalletProvider = EUDITestWalletAttestationProvider()
        let eudiTestIssuerTrust = EUDITestIssuerCertificateTrustSource(
            staticTestPolicy: EUDITestStaticTrustPolicy())
        let issuance = OpenID4VCIClient(
            store: store, keyAttestationProvider: eudiTestProvider,
            keyAttestationTrustSource: eudiTestProvider,
            walletAttestationProvider: eudiTestWalletProvider,
            issuerCertificateTrustSource: eudiTestIssuerTrust)
        return WalletModel(issuance: issuance, store: store)
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
                .environment(demo?.store ?? store)
                .environment(appLock)
                .environment(wallpaper)
                .environment(demo?.wallet ?? wallet)
                .task {
                    store.load()
                    wallet.load()
                }
                .onChange(of: isDemoModeOn) { _, isOn in
                    #if DEBUG
                    guard !ScreenshotDemo.isEnabled else { return }
                    #endif
                    demo?.end()
                    demo = isOn ? DemoMode.Session(fresh: true) : nil
                    if !isOn {
                        // Picks up what AutoFill or iCloud changed while the made-up cards were shown.
                        store.load()
                        wallet.load()
                    }
                }
                // RootView reloads the stores it shows; in Demo Mode the user's own are
                // reloaded here, for AutoFill below.
                .onChange(of: scenePhase) { _, phase in
                    if phase == .active, demo != nil {
                        store.load()
                    }
                }
                // Keeps AutoFill suggestions in step with the cards, including changes
                // that arrive through iCloud. Also runs on each return to the app, in
                // case AutoFill was turned on in Settings meanwhile. Always the user's own
                // cards, also in Demo Mode.
                .task(id: AutoFillRegistration(identities: store.autoFillIdentities, isActive: scenePhase == .active)) {
                    guard scenePhase == .active, !isScreenshotDemo, let identities = store.autoFillIdentities else { return }
                    await CredentialIdentitySync.replace(with: identities)
                }
        }
    }
}

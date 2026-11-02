#if DEBUG
import Foundation
import SwiftUI

/// Fictional accounts for App Store screenshots, kept apart from real data.
///
/// Launch a Debug build with `-screenshotDemo YES`. The accounts live under their
/// own Keychain service and settings domain, so the regular data is untouched.
/// Combine with `-appLockEnabled NO -hasCompletedOnboarding YES -hasSeenTutorial YES`
/// to skip the lock, the first-launch screen, and the tutorial, and with
/// `-screenshotScene <name>` to open one of the `ScreenshotScene` screens.
/// `fastlane screenshots` launches it this way for every screen.
enum ScreenshotDemo {
    private static let suite = "com.authrim.keyring.screenshot-demo"

    static var isEnabled: Bool {
        UserDefaults.standard.bool(forKey: "screenshotDemo")
    }

    /// The screen to open, if any.
    static var scene: ScreenshotScene? {
        guard isEnabled else { return nil }
        return UserDefaults.standard.string(forKey: "screenshotScene").flatMap(ScreenshotScene.init)
    }

    private static var defaults: UserDefaults {
        UserDefaults(suiteName: suite) ?? .standard
    }

    static func makeStore() -> AccountStore {
        UserDefaults().removePersistentDomain(forName: suite)
        let store = AccountStore(keychain: KeychainStore(service: suite), defaults: defaults)
        store.deleteAll()
        for (index, account) in accounts.enumerated() {
            var account = account
            // Keeps the listed order, which falls back to creation time.
            account.createdAt = Date(timeIntervalSince1970: 1_800_000_000 + Double(index))
            store.add(account)
        }
        if let bank = store.accounts.first(where: { $0.issuer == recoveryCodesIssuer }) {
            store.setDetails(AccountDetails(id: bank.id, websites: ["harborbank.example"], recoveryCodes: recoveryCodes))
        }
        if let made = try? Passkey.make(
            relyingParty: "juniper.example",
            userName: "alex@example.com",
            userHandle: Data("alex".utf8),
            deviceOnly: true
        ) {
            var passkey = made.passkey
            passkey.customTitle = "Juniper Travel"
            passkey.cardColor = CardColor.presets[4]
            passkey.createdAt = .now.addingTimeInterval(-40 * 24 * 3600)
            passkey.lastUsedAt = .now.addingTimeInterval(-2 * 3600)
            try? store.addPasskey(passkey)
            // Third, so the home screen shows a passkey among the codes.
            store.move(fromOffsets: IndexSet(integer: store.items.count - 1), toOffset: 2)
        }
        return store
    }

    /// Takes `-appLockEnabled` from the launch arguments, which only reach the
    /// app's own settings, not the App Group the lock normally reads. The lock
    /// shows as on in Settings but starts unlocked, so no Face ID is needed.
    static func makeAppLock() -> AppLock {
        defaults.set(UserDefaults.standard.bool(forKey: SharedDefaults.appLockKey), forKey: SharedDefaults.appLockKey)
        let appLock = AppLock(defaults: defaults)
        appLock.unlockForScreenshots()
        return appLock
    }

    /// The default wallpaper, whatever this device has chosen; its photo is left alone.
    static func makeWallpaper() -> WallpaperStore {
        WallpaperStore(defaults: defaults, keepsPhoto: false)
    }

    /// The card whose code the code screenshot shows.
    static let codeIssuer = "Northwind Mail"
    static let recoveryCodesIssuer = "Harbor Bank"

    /// What the import screenshot lists, as if read from Google Authenticator.
    static var importedAccounts: ImportedAccounts {
        var imported = ImportedAccounts()
        let names: [(String, String)] = [
            ("Northwind Mail", "alex@northwind.example"),
            ("Orbit Chat", "alex"),
            ("Cedar Games", "alex.morgan"),
            ("Willow Docs", "alex@example.com"),
            ("Tidal Pay", "alex@example.com"),
        ]
        for (index, name) in names.enumerated() {
            // The first one matches a card already here, as moving often includes.
            let seed = name.0 == codeIssuer ? 2 : UInt8(20 + index)
            imported.add(OTPAccount(issuer: name.0, accountName: name.1, secret: secret(seed)), label: name.0)
        }
        return imported
    }

    private static let accounts: [OTPAccount] = [
        OTPAccount(issuer: "Authrim", accountName: "alex@example.com", secret: secret(1), cardColor: CardColor.presets[0]),
        OTPAccount(issuer: "Northwind Mail", accountName: "alex@northwind.example", secret: secret(2), cardColor: CardColor.presets[1]),
        OTPAccount(issuer: "Acme Cloud", accountName: "admin@acme.example", secret: secret(3), cardColor: CardColor.presets[10]),
        OTPAccount(issuer: "Harbor Bank", accountName: "alex.morgan", secret: secret(4), cardColor: CardColor.presets[6]),
        OTPAccount(issuer: "Fern Notes", accountName: "alex@example.com", secret: secret(5), cardColor: CardColor.presets[3]),
        OTPAccount(issuer: "Lumen Shop", accountName: "alex", secret: secret(6), cardColor: CardColor.presets[12]),
        OTPAccount(issuer: "Pixel Forge", accountName: "alex@pixelforge.example", secret: secret(7), cardColor: CardColor.presets[2]),
    ]

    /// Ten made-up codes, the first two used.
    private static var recoveryCodes: [RecoveryCode] {
        let codes = ["k7qm-2xpd", "r4tn-8wvb", "c9hz-3fje", "m2ua-6kyr", "p8ds-1lqx",
                     "w5gb-7nct", "h3vk-9ezm", "t6yp-4rau", "f1xw-5jds", "n8ce-2hgv"]
        return codes.enumerated().map { index, code in
            RecoveryCode(code: code, usedAt: index < 2 ? .now.addingTimeInterval(-Double(index + 3) * 24 * 3600) : nil)
        }
    }

    private static func secret(_ seed: UInt8) -> Data {
        Data((0..<20).map { UInt8(truncatingIfNeeded: Int($0) * 37 + Int(seed) * 101) })
    }
}

/// Screens `fastlane screenshots` opens with `-screenshotScene`.
enum ScreenshotScene: String, Identifiable {
    /// The cards, with nothing open.
    case home
    /// A card opened to its code.
    case code
    /// The passkey card opened.
    case passkey
    /// Accounts read from another app, before they are added.
    case importAccounts = "import"
    /// A card's recovery codes, shown.
    case recoveryCodes = "recovery"
    case wallpaper
    case settings

    var id: String { rawValue }
}

/// What a scene shows in a sheet over the home screen.
struct ScreenshotSceneSheet: View {
    @Environment(AccountStore.self) private var store
    let scene: ScreenshotScene

    var body: some View {
        NavigationStack {
            switch scene {
            case .importAccounts:
                ImportPreviewView(imported: ScreenshotDemo.importedAccounts) {}
            case .recoveryCodes:
                if let bank = store.accounts.first(where: { $0.issuer == ScreenshotDemo.recoveryCodesIssuer }) {
                    RecoveryCodesView(accountID: bank.id)
                }
            case .wallpaper:
                WallpaperSettingsView()
            default:
                EmptyView()
            }
        }
    }
}
#endif

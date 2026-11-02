#if DEBUG
import Foundation

/// Fictional accounts for App Store screenshots, kept apart from real data.
///
/// Launch a Debug build with `-screenshotDemo YES`. The accounts live under their
/// own Keychain service and settings domain, so the regular data is untouched.
/// Combine with `-appLockEnabled NO -hasCompletedOnboarding YES -hasSeenTutorial YES`
/// to skip the lock, the first-launch screen, and the tutorial.
enum ScreenshotDemo {
    private static let suite = "com.authrim.keyring.screenshot-demo"

    static var isEnabled: Bool {
        UserDefaults.standard.bool(forKey: "screenshotDemo")
    }

    static func makeStore() -> AccountStore {
        UserDefaults().removePersistentDomain(forName: suite)
        let store = AccountStore(
            keychain: KeychainStore(service: suite),
            defaults: UserDefaults(suiteName: suite) ?? .standard
        )
        store.deleteAll()
        for (index, account) in accounts.enumerated() {
            var account = account
            // Keeps the listed order, which falls back to creation time.
            account.createdAt = Date(timeIntervalSince1970: 1_800_000_000 + Double(index))
            store.add(account)
        }
        return store
    }

    /// Takes `-appLockEnabled` from the launch arguments, which only reach the
    /// app's own settings, not the App Group the lock normally reads.
    static func makeAppLock() -> AppLock {
        let defaults = UserDefaults(suiteName: suite) ?? .standard
        defaults.set(UserDefaults.standard.bool(forKey: SharedDefaults.appLockKey), forKey: SharedDefaults.appLockKey)
        return AppLock(defaults: defaults)
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

    private static func secret(_ seed: UInt8) -> Data {
        Data((0..<20).map { UInt8(truncatingIfNeeded: Int($0) * 37 + Int(seed) * 101) })
    }
}
#endif

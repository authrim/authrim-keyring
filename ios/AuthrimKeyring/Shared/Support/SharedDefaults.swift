import Foundation

/// Settings read by both the app and the AutoFill extension, kept in the App Group.
nonisolated enum SharedDefaults {
    static let suiteName = "group.com.authrim.keyring"

    static let syncKey = "iCloudSyncEnabled"
    static let appLockKey = "appLockEnabled"
    static let orderKey = "accountOrder"

    /// Never the app's own settings: after the move those hold stale values, such
    /// as a lock that has since been turned on.
    static var store: UserDefaults {
        // Only nil for the app's own identifier or the global domain.
        UserDefaults(suiteName: suiteName)!
    }

    private static let migratedKey = "migratedToAppGroup"

    /// False until the app has run once after updating from 1.0. Until then the
    /// lock setting here may be missing, so the extension must not trust it.
    static var hasMigrated: Bool {
        store.persistentDomain(forName: suiteName)?[migratedKey] as? Bool == true
    }

    private static let movedKeys = [syncKey, appLockKey, orderKey]

    /// Copies the settings version 1.0 kept in the app's own domain. Both sides are
    /// read from what is saved, so launch arguments such as `-appLockEnabled NO`
    /// neither get copied in nor hide a value that still needs copying.
    static func migrateFromStandard() {
        let shared = store
        let saved = shared.persistentDomain(forName: suiteName) ?? [:]
        guard saved[migratedKey] as? Bool != true else { return }
        if let bundleID = Bundle.main.bundleIdentifier,
           let old = UserDefaults.standard.persistentDomain(forName: bundleID) {
            for key in movedKeys where saved[key] == nil {
                if let value = old[key] {
                    shared.set(value, forKey: key)
                }
            }
        }
        shared.set(true, forKey: migratedKey)
    }
}

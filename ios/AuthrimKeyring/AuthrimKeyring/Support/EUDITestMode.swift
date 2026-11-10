import Foundation

/// User opt-in for Keyring's narrowly scoped reference-issuer interoperability policy.
/// These preferences never replace signature, certificate, expiry or issuer checks.
nonisolated enum EUDITestMode {
    static let enabledKey = "eudiTestModeEnabled"
    static let pidKey = "eudiTestPIDEnabled"
    static let pubEAAKey = "eudiTestPubEAAEnabled"
    static let otherKey = "eudiTestOtherCredentialsEnabled"

    enum Category: Hashable, Sendable {
        case pid
        case pubEAA
        case other

        var key: String {
            switch self {
            case .pid: EUDITestMode.pidKey
            case .pubEAA: EUDITestMode.pubEAAKey
            case .other: EUDITestMode.otherKey
            }
        }
    }

    static func isEnabled(_ category: Category) -> Bool {
        isEnabled(category, defaults: .standard)
    }

    static func isEnabled(_ category: Category, defaults: UserDefaults) -> Bool {
        guard defaults.bool(forKey: enabledKey) else { return false }
        return defaults.object(forKey: category.key) as? Bool ?? true
    }
}

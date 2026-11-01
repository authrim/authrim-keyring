import Foundation
import LocalAuthentication
import Observation

/// Optional Face ID / Touch ID / passcode lock for opening the app.
@Observable
final class AppLock {
    private static let enabledKey = "appLockEnabled"

    private(set) var isEnabled: Bool
    private(set) var isUnlocked: Bool
    private(set) var isAuthenticating = false
    /// Set when the app launches or returns from the background. The Face ID sheet
    /// itself makes the scene inactive, so prompting on every activation would
    /// re-prompt forever after the user cancels.
    private var shouldPromptOnActivation: Bool

    init() {
        let enabled = UserDefaults.standard.bool(forKey: Self.enabledKey)
        isEnabled = enabled
        isUnlocked = !enabled
        shouldPromptOnActivation = enabled
    }

    var isLocked: Bool { isEnabled && !isUnlocked }

    var biometryName: String {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        return switch context.biometryType {
        case .faceID: String(localized: "Face ID")
        case .touchID: String(localized: "Touch ID")
        case .opticID: String(localized: "Optic ID")
        default: String(localized: "Passcode")
        }
    }

    var canUseDeviceAuthentication: Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
    }

    func lock() {
        guard isEnabled else { return }
        isUnlocked = false
        shouldPromptOnActivation = true
    }

    /// Prompts automatically once per launch or return from the background.
    func unlockOnActivation() async {
        guard shouldPromptOnActivation else { return }
        shouldPromptOnActivation = false
        await unlock()
    }

    func unlock() async {
        guard isLocked, !isAuthenticating else { return }
        if await authenticate(reason: String(localized: "Unlock Authrim Keyring to view your codes.")) {
            isUnlocked = true
        }
    }

    /// Changing the setting always requires the device owner, so a briefly
    /// unattended phone cannot be used to turn the lock off.
    func setEnabled(_ enabled: Bool) async {
        guard enabled != isEnabled else { return }
        let reason = enabled
            ? String(localized: "Turn on the app lock.")
            : String(localized: "Turn off the app lock.")
        guard await authenticate(reason: reason) else { return }
        isEnabled = enabled
        isUnlocked = true
        UserDefaults.standard.set(enabled, forKey: Self.enabledKey)
    }

    private func authenticate(reason: String) async -> Bool {
        isAuthenticating = true
        defer { isAuthenticating = false }
        let context = LAContext()
        do {
            return try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
        } catch {
            return false
        }
    }
}

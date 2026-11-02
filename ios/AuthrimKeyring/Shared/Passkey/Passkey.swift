import CryptoKit
import Foundation

/// A passkey Keyring created for a website, stored as its own Keychain item.
nonisolated struct Passkey: Codable, Identifiable, Hashable, Sendable {
    var id: UUID
    /// The identifier the relying party stores; random, 16 bytes.
    var credentialID: Data
    /// The site's relying party identifier, such as `example.com`.
    var relyingParty: String
    var userName: String
    /// The relying party's identifier for the account, returned when signing in.
    var userHandle: Data
    var createdAt: Date
    var lastUsedAt: Date?
    /// False for a passkey kept on this device only, which Keyring never syncs or
    /// backs up. Fixed when the passkey is created. (Sites see every passkey as
    /// synced, since iOS requires it; see `WebAuthn.flags`.)
    var isBackupEligible: Bool
    /// Whether `privateKey` is the Secure Enclave's wrapped handle to a key that
    /// never leaves it, rather than the key itself.
    var isInSecureEnclave: Bool
    /// The P-256 private key, or the Secure Enclave handle, useless on any other device.
    var privateKey: Data
    /// A name the user gave the card; the site is shown otherwise.
    var customTitle: String?
    var cardColor: CardColor?

    var displayTitle: String {
        customTitle.flatMap { $0.isEmpty ? nil : $0 } ?? relyingParty
    }

    var displaySubtitle: String? {
        userName.isEmpty ? nil : userName
    }

    var effectiveCardColor: CardColor {
        cardColor ?? .automatic(for: relyingParty)
    }

    /// Creates the key for a new passkey.
    static func make(
        relyingParty: String,
        userName: String,
        userHandle: Data,
        deviceOnly: Bool,
        now: Date = .now
    ) throws -> (passkey: Passkey, publicKey: P256.Signing.PublicKey) {
        var credentialID = Data(count: 16)
        let status = credentialID.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!)
        }
        guard status == errSecSuccess else { throw PasskeyError.randomFailed }

        let privateKey: Data
        let publicKey: P256.Signing.PublicKey
        // A device-only key goes in the Secure Enclave where there is one; otherwise
        // (the simulator) it is still kept only in this device's Keychain.
        let useSecureEnclave = deviceOnly && SecureEnclave.isAvailable
        if useSecureEnclave {
            let key = try SecureEnclave.P256.Signing.PrivateKey()
            privateKey = key.dataRepresentation
            publicKey = key.publicKey
        } else {
            let key = P256.Signing.PrivateKey()
            privateKey = key.rawRepresentation
            publicKey = key.publicKey
        }
        let passkey = Passkey(
            id: UUID(),
            credentialID: credentialID,
            relyingParty: relyingParty,
            userName: userName,
            userHandle: userHandle,
            createdAt: now,
            isBackupEligible: !deviceOnly,
            isInSecureEnclave: useSecureEnclave,
            privateKey: privateKey
        )
        return (passkey, publicKey)
    }

    /// Signs `authenticatorData ‖ clientDataHash` for an assertion, DER encoded.
    func sign(_ message: Data) throws -> Data {
        if isInSecureEnclave {
            let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: privateKey)
            return try key.signature(for: message).derRepresentation
        } else {
            let key = try P256.Signing.PrivateKey(rawRepresentation: privateKey)
            return try key.signature(for: message).derRepresentation
        }
    }
}

nonisolated enum PasskeyError: LocalizedError {
    case randomFailed
    case unsupportedAlgorithm

    var errorDescription: String? {
        switch self {
        case .randomFailed:
            String(localized: "A secure random number could not be generated.")
        case .unsupportedAlgorithm:
            String(localized: "The site asked for a kind of passkey Keyring cannot create.")
        }
    }
}

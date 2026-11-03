import Foundation

/// Credentials as device-only generic-password Keychain items under their own service.
///
/// Reuses `KeychainStore` at `.device`: `WhenUnlockedThisDeviceOnly`, not synchronizable, data-protection
/// keychain. The service `com.authrim.keyring.vc` is not touched by any other code path: the
/// TOTP/passkey/details/meta stores use `com.authrim.keyring.totp[.suffix]` (and `deleteAll` there matches
/// the exact service), iCloud sync only moves those services and the encrypted backup export is built
/// from `AccountStore` items, so wallet credentials never reach iCloud or a backup file. Holder keys are
/// Secure Enclave keys under their own tags and cannot be exported at all.
nonisolated struct KeychainCredentialStore: CredentialStore {
    static let service = "com.authrim.keyring.vc"

    private let keychain: KeychainStore
    private let deleteKey: @Sendable (String) throws -> Void

    init(
        service: String = KeychainCredentialStore.service,
        deleteKey: @escaping @Sendable (String) throws -> Void = { try HolderKey.delete(tag: $0) }
    ) {
        keychain = KeychainStore(service: service)
        self.deleteKey = deleteKey
    }

    func loadAll() throws -> [StoredCredential] {
        do {
            return try keychain.loadAll(StoredCredential.self, from: .device).sorted { $0.issuedAt > $1.issuedAt }
        } catch { throw WalletError.storage(error.localizedDescription) }
    }

    func save(_ credential: StoredCredential) throws {
        do { try keychain.save(credential, to: .device) } catch { throw WalletError.storage(error.localizedDescription) }
    }

    /// Deletes the holder key first, then the item, so a failed key deletion keeps the credential visible.
    func delete(_ credential: StoredCredential) throws {
        do {
            try deleteKey(credential.keyTag)
            try keychain.delete(id: credential.id, from: .device)
        } catch let error as WalletError {
            throw error
        } catch { throw WalletError.storage(error.localizedDescription) }
    }
}

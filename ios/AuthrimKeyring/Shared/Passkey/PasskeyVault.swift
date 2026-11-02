import Foundation

/// Where passkeys are kept. A synced passkey follows the sync setting like the
/// accounts; a device-only one always stays in this device's Keychain.
nonisolated struct PasskeyVault {
    let keychain: KeychainStore

    init(base: KeychainStore) {
        keychain = KeychainStore(service: base.service + ".passkey")
    }

    func loadAll(syncEnabled: Bool) throws -> [Passkey] {
        let local = try keychain.loadAll(Passkey.self, from: .device)
        guard syncEnabled else { return local }
        // While syncing, eligible ones on this device are leftovers of an interrupted switch.
        let synced = try keychain.loadAll(Passkey.self, from: .iCloud)
        return synced.filter(\.isBackupEligible) + local.filter { !$0.isBackupEligible }
    }

    func save(_ passkey: Passkey, syncEnabled: Bool) throws {
        try keychain.save(passkey, to: location(of: passkey, syncEnabled: syncEnabled))
    }

    func delete(_ passkey: Passkey, syncEnabled: Bool) throws {
        try keychain.delete(id: passkey.id, from: location(of: passkey, syncEnabled: syncEnabled))
    }

    /// Passkeys in iCloud Keychain, for telling the user what sync would bring back.
    func countInICloud() throws -> Int {
        try keychain.loadAll(Passkey.self, from: .iCloud).count
    }

    func location(of passkey: Passkey, syncEnabled: Bool) -> KeychainStore.Location {
        passkey.isBackupEligible && syncEnabled ? .iCloud : .device
    }

    /// Copies the synced passkeys on this device into iCloud Keychain, adding the
    /// identifiers it creates there to `created`, so a failed switch can take them back.
    func copyToICloud(created: inout [UUID]) throws {
        let local = try keychain.loadAll(Passkey.self, from: .device).filter(\.isBackupEligible)
        let existing = Set(try keychain.loadAll(Passkey.self, from: .iCloud).map(\.id))
        for passkey in local {
            try keychain.save(passkey, to: .iCloud)
            if !existing.contains(passkey.id) {
                created.append(passkey.id)
            }
        }
    }

    /// Removes the device copies of synced passkeys once iCloud holds them.
    func removeSyncedCopiesFromDevice() {
        guard let local = try? keychain.loadAll(Passkey.self, from: .device) else { return }
        for passkey in local where passkey.isBackupEligible {
            try? keychain.delete(id: passkey.id, from: .device)
        }
    }

    /// Copies the passkeys in iCloud Keychain onto this device. Returns what it copied.
    func copyToDevice() throws -> [Passkey] {
        let synced = try keychain.loadAll(Passkey.self, from: .iCloud)
        for passkey in synced {
            try keychain.save(passkey, to: .device)
        }
        // A synced passkey left here by an earlier, interrupted switch may have been
        // deleted in iCloud since; it must not come back. Device-only ones stay.
        let current = Set(synced.map(\.id))
        for passkey in try keychain.loadAll(Passkey.self, from: .device)
        where passkey.isBackupEligible && !current.contains(passkey.id) {
            try keychain.delete(id: passkey.id, from: .device)
        }
        return synced
    }

    func deleteFromICloud(_ ids: [UUID]) throws {
        for id in ids {
            try keychain.delete(id: id, from: .iCloud)
        }
    }

    func deleteAll(includingICloud: Bool) throws {
        try keychain.deleteAll(from: .device)
        if includingICloud {
            try keychain.deleteAll(from: .iCloud)
        }
    }
}

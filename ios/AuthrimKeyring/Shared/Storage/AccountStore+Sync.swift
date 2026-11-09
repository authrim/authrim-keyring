import Foundation

/// Moving everything between this device and iCloud Keychain.
extension AccountStore {
    /// Moves every account between this device and iCloud Keychain.
    ///
    /// Turning sync on merges this device's accounts into iCloud Keychain. Turning it
    /// off copies the accounts back onto this device; `removeFromICloud` also deletes
    /// those iCloud copies, which removes them from the user's other devices.
    ///
    /// The setting is saved after the copies are written and before the originals are
    /// deleted, so an interruption at any point leaves the setting pointing at a
    /// complete set of accounts.
    @discardableResult
    func setSyncEnabled(_ enabled: Bool, removeFromICloud: Bool = false) -> Bool {
        guard enabled != isSyncEnabled else { return true }
        defer { load() }
        do {
            // Locked, so the AutoFill extension cannot advance a counter in the copy being left behind.
            try CounterLock.withLock {
                if enabled {
                    try moveToICloud()
                } else {
                    try moveToDevice(removeFromICloud: removeFromICloud)
                }
            }
            return true
        } catch {
            lastError = error.localizedDescription
            return false
        }
    }

    private func moveToICloud() throws {
        // Read again rather than trusting `accounts`, which may be out of date. The
        // copies here are deleted afterwards, so every one of them must be read.
        let (local, skippedLocal) = try keychain.loadAllCountingSkipped(from: .device)
        var synced = try keychain.loadAll(from: .iCloud)
        let (localDetailsList, skippedDetails) = try detailsKeychain.loadAllCountingSkipped(AccountDetails.self, from: .device)
        let localDetails = Dictionary(localDetailsList.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        var syncedDetails = try detailsByID(in: .iCloud)
        let (localMeta, skippedMeta) = try metaKeychain.loadAllCountingSkipped(ItemMeta.self, from: .device)
        var syncedMeta = try metaByID(in: .iCloud)
        guard skippedLocal + skippedDetails + skippedMeta == 0 else { throw SyncError.unreadableItems }
        var created: [UUID] = []
        var createdDetails: [UUID] = []
        var createdMeta: [UUID] = []
        var createdPasskeys: [UUID] = []
        var renamedIDs: [UUID: UUID] = [:]
        do {
            for var account in local {
                let localID = account.id
                var isMerged = false
                if let match = synced.first(where: { $0.generatesSameCodes(as: account) }) {
                    // Codes either copy has handed out must not be handed out again.
                    account.kind = Self.later(account.kind, match.kind)
                    // The same key added separately on another device stays as one card.
                    if match.id != account.id {
                        renamedIDs[account.id] = match.id
                        account.id = match.id
                        isMerged = true
                        if account.kind != match.kind {
                            var advanced = match
                            advanced.kind = account.kind
                            try keychain.save(advanced, to: .iCloud)
                            // Another card here with the same key compares against this.
                            if let index = synced.firstIndex(where: { $0.id == match.id }) {
                                synced[index] = advanced
                            }
                        }
                    }
                } else if synced.contains(where: { $0.id == account.id }) {
                    // Same identifier but a different key: keep both instead of overwriting.
                    let newID = UUID()
                    renamedIDs[account.id] = newID
                    account.id = newID
                }
                if !isMerged {
                    let existing = synced.firstIndex { $0.id == account.id }
                    try keychain.save(account, to: .iCloud)
                    if let existing {
                        synced[existing] = account
                    } else {
                        created.append(account.id)
                    }
                }
                if let extra = localDetails[localID] {
                    var merged = (syncedDetails[account.id] ?? AccountDetails(id: account.id)).merging(extra)
                    merged.id = account.id
                    if syncedDetails[account.id] == nil {
                        createdDetails.append(account.id)
                    }
                    try detailsKeychain.save(merged, to: .iCloud)
                    // Another card here may merge into the same synced one.
                    syncedDetails[account.id] = merged
                }
            }
            try passkeyVault.copyToICloud(created: &createdPasskeys)
            // Favorites and tags follow their cards, wherever those were merged.
            for note in localMeta {
                let id = renamedIDs[note.id] ?? note.id
                let existing = syncedMeta[id]
                let merged = (existing ?? ItemMeta(id: id)).merging(note)
                if existing == nil {
                    createdMeta.append(id)
                }
                try metaKeychain.save(merged, to: .iCloud)
                syncedMeta[id] = merged
            }
        } catch {
            // Takes back what this attempt added, so the keys do not linger in iCloud.
            for id in created {
                try? keychain.delete(id: id, from: .iCloud)
            }
            for id in createdDetails {
                try? detailsKeychain.delete(id: id, from: .iCloud)
            }
            for id in createdMeta {
                try? metaKeychain.delete(id: id, from: .iCloud)
            }
            try? passkeyVault.deleteFromICloud(createdPasskeys)
            throw error
        }
        replaceInOrder(renamedIDs)
        saveSyncSetting(true)
        // Anything left here is a redundant copy, cleared again when sync is turned off.
        try? keychain.deleteAll(from: .device)
        try? detailsKeychain.deleteAll(from: .device)
        try? metaKeychain.deleteAll(from: .device)
        passkeyVault.removeSyncedCopiesFromDevice()
    }

    private func moveToDevice(removeFromICloud: Bool) throws {
        let synced = try keychain.loadAll(from: .iCloud)
        let syncedDetails = try detailsKeychain.loadAll(AccountDetails.self, from: .iCloud)
        let syncedMeta = try metaKeychain.loadAll(ItemMeta.self, from: .iCloud)
        // While sync is on, items on this device are only leftovers of an interrupted switch.
        try keychain.deleteAll(from: .device)
        try detailsKeychain.deleteAll(from: .device)
        try metaKeychain.deleteAll(from: .device)
        for account in synced {
            try keychain.save(account, to: .device)
        }
        for extra in syncedDetails {
            try detailsKeychain.save(extra, to: .device)
        }
        for note in syncedMeta {
            try metaKeychain.save(note, to: .device)
        }
        let syncedPasskeys = try passkeyVault.copyToDevice()
        saveSyncSetting(false)
        if removeFromICloud {
            // Only the items copied above, not ones that arrived in the meantime.
            for account in synced {
                try keychain.delete(id: account.id, from: .iCloud)
            }
            for extra in syncedDetails {
                try detailsKeychain.delete(id: extra.id, from: .iCloud)
            }
            for note in syncedMeta {
                try metaKeychain.delete(id: note.id, from: .iCloud)
            }
            try passkeyVault.deleteFromICloud(syncedPasskeys.map(\.id))
        }
    }

    enum SyncError: LocalizedError {
        case unreadableItems

        var errorDescription: String? {
            String(localized: "Some cards on this device could not be read, so sync was not turned on. Try again after restarting the app.")
        }
    }

    private func metaByID(in location: KeychainStore.Location) throws -> [UUID: ItemMeta] {
        let loaded = try metaKeychain.loadAll(ItemMeta.self, from: location)
        return Dictionary(loaded.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
    }

    private func detailsByID(in location: KeychainStore.Location) throws -> [UUID: AccountDetails] {
        let loaded = try detailsKeychain.loadAll(AccountDetails.self, from: location)
        return Dictionary(loaded.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
    }
}

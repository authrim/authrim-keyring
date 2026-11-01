import Foundation
import Observation
import SwiftUI

@Observable
final class AccountStore {
    private static let orderKey = "accountOrder"
    private static let syncKey = "iCloudSyncEnabled"

    private(set) var accounts: [OTPAccount] = []
    /// Whether accounts are kept in iCloud Keychain rather than on this device only.
    private(set) var isSyncEnabled: Bool
    /// Accounts in iCloud Keychain while sync is off here, e.g. on a new device.
    private(set) var iCloudAccountCount = 0
    var lastError: String?

    private let keychain: KeychainStore
    private let defaults: UserDefaults

    init(keychain: KeychainStore = KeychainStore(), defaults: UserDefaults = .standard) {
        self.keychain = keychain
        self.defaults = defaults
        isSyncEnabled = defaults.bool(forKey: Self.syncKey)
    }

    private var location: KeychainStore.Location { isSyncEnabled ? .iCloud : .device }

    func load() {
        do {
            let loaded = try keychain.loadAll(from: location)
            // The display order is kept separately so a reorder is a single write.
            let order = defaults.stringArray(forKey: Self.orderKey) ?? []
            let position = Dictionary(
                order.enumerated().map { ($0.element, $0.offset) },
                uniquingKeysWith: { first, _ in first }
            )
            accounts = loaded.sorted { lhs, rhs in
                let left = position[lhs.id.uuidString] ?? Int.max
                let right = position[rhs.id.uuidString] ?? Int.max
                return left != right ? left < right : lhs.createdAt < rhs.createdAt
            }
            // Only a hint, so a failure here should not hide the accounts.
            iCloudAccountCount = isSyncEnabled ? 0 : (try? keychain.loadAll(from: .iCloud).count) ?? 0
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// True when an account with the same secret and parameters is already registered.
    func containsDuplicate(of candidate: OTPAccount) -> Bool {
        accounts.contains { $0.generatesSameCodes(as: candidate) }
    }

    @discardableResult
    func add(_ account: OTPAccount) -> Bool {
        do {
            try insert(account)
            return true
        } catch {
            lastError = error.localizedDescription
            return false
        }
    }

    func update(_ id: UUID, issuer: String, accountName: String, cardColor: CardColor?) {
        guard let index = accounts.firstIndex(where: { $0.id == id }) else { return }
        var account = accounts[index]
        account.issuer = issuer
        account.accountName = accountName
        account.cardColor = cardColor
        do {
            try keychain.save(account, to: location)
            accounts[index] = account
        } catch {
            lastError = error.localizedDescription
        }
    }

    func delete(_ id: UUID) {
        do {
            try keychain.delete(id: id, from: location)
            accounts.removeAll { $0.id == id }
            saveOrder()
        } catch {
            lastError = error.localizedDescription
        }
    }

    func move(fromOffsets source: IndexSet, toOffset destination: Int) {
        accounts.move(fromOffsets: source, toOffset: destination)
        saveOrder()
    }

    /// Deletes every account here. With sync off, `includingICloud` also deletes
    /// the copies kept in iCloud Keychain, which removes them from other devices.
    func deleteAll(includingICloud: Bool = false) {
        do {
            try keychain.deleteAll(from: location)
            if includingICloud, !isSyncEnabled {
                try keychain.deleteAll(from: .iCloud)
            }
            defaults.removeObject(forKey: Self.orderKey)
        } catch {
            lastError = error.localizedDescription
        }
        load()
    }

    struct ImportResult {
        var added: Int
        /// Set when saving stopped partway; the accounts before it were added.
        var error: String?
    }

    /// Adds accounts restored from a backup, skipping ones that are already here.
    func importAccounts(_ incoming: [OTPAccount]) -> ImportResult {
        // Checks against the Keychain, not a list that iCloud may have changed since,
        // so an imported account never overwrites an existing item in place.
        load()
        var added = 0
        for var account in incoming where !containsDuplicate(of: account) {
            if accounts.contains(where: { $0.id == account.id }) {
                account.id = UUID()
            }
            do {
                try insert(account)
            } catch {
                return ImportResult(added: added, error: error.localizedDescription)
            }
            added += 1
        }
        return ImportResult(added: added, error: nil)
    }

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
            if enabled {
                try moveToICloud()
            } else {
                try moveToDevice(removeFromICloud: removeFromICloud)
            }
            return true
        } catch {
            lastError = error.localizedDescription
            return false
        }
    }

    private func moveToICloud() throws {
        // Read again rather than trusting `accounts`, which may be out of date.
        let local = try keychain.loadAll(from: .device)
        let synced = try keychain.loadAll(from: .iCloud)
        var created: [UUID] = []
        var renamedIDs: [UUID: UUID] = [:]
        do {
            for var account in local {
                if let match = synced.first(where: { $0.generatesSameCodes(as: account) }) {
                    // The same key added separately on another device stays as one card.
                    if match.id != account.id {
                        renamedIDs[account.id] = match.id
                        continue
                    }
                } else if synced.contains(where: { $0.id == account.id }) {
                    // Same identifier but a different key: keep both instead of overwriting.
                    let newID = UUID()
                    renamedIDs[account.id] = newID
                    account.id = newID
                }
                let isNew = !synced.contains { $0.id == account.id }
                try keychain.save(account, to: .iCloud)
                if isNew {
                    created.append(account.id)
                }
            }
        } catch {
            // Takes back what this attempt added, so the keys do not linger in iCloud.
            for id in created {
                try? keychain.delete(id: id, from: .iCloud)
            }
            throw error
        }
        replaceInOrder(renamedIDs)
        saveSyncSetting(true)
        // Anything left here is a redundant copy, cleared again when sync is turned off.
        try? keychain.deleteAll(from: .device)
    }

    private func moveToDevice(removeFromICloud: Bool) throws {
        let synced = try keychain.loadAll(from: .iCloud)
        // While sync is on, items on this device are only leftovers of an interrupted switch.
        try keychain.deleteAll(from: .device)
        for account in synced {
            try keychain.save(account, to: .device)
        }
        saveSyncSetting(false)
        if removeFromICloud {
            // Only the accounts copied above, not ones that arrived in the meantime.
            for account in synced {
                try keychain.delete(id: account.id, from: .iCloud)
            }
        }
    }

    private func insert(_ account: OTPAccount) throws {
        try keychain.save(account, to: location)
        accounts.append(account)
        saveOrder()
    }

    private func saveSyncSetting(_ enabled: Bool) {
        isSyncEnabled = enabled
        defaults.set(enabled, forKey: Self.syncKey)
    }

    /// Keeps a card in place on this device when its identifier changes.
    private func replaceInOrder(_ renamedIDs: [UUID: UUID]) {
        guard !renamedIDs.isEmpty, let order = defaults.stringArray(forKey: Self.orderKey) else { return }
        let renamed = Dictionary(uniqueKeysWithValues: renamedIDs.map { ($0.key.uuidString, $0.value.uuidString) })
        defaults.set(order.map { renamed[$0] ?? $0 }, forKey: Self.orderKey)
    }

    private func saveOrder() {
        defaults.set(accounts.map(\.id.uuidString), forKey: Self.orderKey)
    }
}

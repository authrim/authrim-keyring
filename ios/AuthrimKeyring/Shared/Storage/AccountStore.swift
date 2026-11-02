import Foundation
import Observation
import SwiftUI

@Observable
final class AccountStore {
    private static let orderKey = SharedDefaults.orderKey
    private static let syncKey = SharedDefaults.syncKey

    private(set) var accounts: [OTPAccount] = []
    private(set) var passkeys: [Passkey] = []
    /// Websites and recovery codes, by account; accounts without any are absent.
    private(set) var details: [UUID: AccountDetails] = [:]
    /// Set until the details have been read, so an edit cannot overwrite what is
    /// actually stored with a partial copy.
    private(set) var areDetailsUnavailable = true
    /// Set until the accounts and passkeys have been read. Until then the lists may
    /// be empty only because reading failed, which must not count as "none".
    private(set) var isContentUnavailable = true
    /// Set until every passkey has been read, so one that could not be is never
    /// taken for absent, as when checking for a passkey a site already has.
    private(set) var arePasskeysUnavailable = true
    /// Whether accounts are kept in iCloud Keychain rather than on this device only.
    private(set) var isSyncEnabled: Bool
    /// Accounts and passkeys in iCloud Keychain while sync is off here, e.g. on a new device.
    private(set) var iCloudAccountCount = 0
    var lastError: String?

    private let keychain: KeychainStore
    private let detailsKeychain: KeychainStore
    private let passkeyVault: PasskeyVault
    private let defaults: UserDefaults
    /// Identifiers of every card in display order, as saved.
    private var order: [String] = []

    init(keychain: KeychainStore = KeychainStore(), defaults: UserDefaults = SharedDefaults.store) {
        self.keychain = keychain
        detailsKeychain = KeychainStore(service: keychain.service + ".details")
        passkeyVault = PasskeyVault(base: keychain)
        self.defaults = defaults
        isSyncEnabled = defaults.bool(forKey: Self.syncKey)
    }

    private var location: KeychainStore.Location { isSyncEnabled ? .iCloud : .device }

    func load() {
        // Fails closed: only a successful read below clears these.
        areDetailsUnavailable = true
        isContentUnavailable = true
        arePasskeysUnavailable = true
        // Read on its own, so trouble with the accounts does not stop passkeys.
        do {
            let (loadedPasskeys, skippedPasskeys) = try passkeyVault.loadAll(syncEnabled: isSyncEnabled)
            passkeys = loadedPasskeys
            arePasskeysUnavailable = skippedPasskeys > 0
        } catch {
            lastError = error.localizedDescription
        }
        do {
            let (loaded, skippedAccounts) = try keychain.loadAllCountingSkipped(OTPAccount.self, from: location)
            // The display order is kept separately so a reorder is a single write.
            order = defaults.stringArray(forKey: Self.orderKey) ?? []
            let position = positions()
            accounts = loaded.sorted { lhs, rhs in
                let left = position[lhs.id.uuidString] ?? Int.max
                let right = position[rhs.id.uuidString] ?? Int.max
                return left != right ? left < right : lhs.createdAt < rhs.createdAt
            }
            // What can be read is shown, but an item that could not be decoded keeps
            // the lists from counting as complete.
            isContentUnavailable = skippedAccounts > 0 || arePasskeysUnavailable
            // Extras should not hide the accounts if they cannot be read.
            if let (loadedDetails, skippedDetails) = try? detailsKeychain.loadAllCountingSkipped(AccountDetails.self, from: location) {
                details = Dictionary(loadedDetails.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
                areDetailsUnavailable = skippedDetails > 0
            }
            // Only a hint, so a failure here should not hide the accounts.
            iCloudAccountCount = isSyncEnabled ? 0
                : ((try? keychain.loadAll(from: .iCloud).count) ?? 0) + ((try? passkeyVault.countInICloud()) ?? 0)
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

    func details(for id: UUID) -> AccountDetails {
        details[id] ?? AccountDetails(id: id)
    }

    @discardableResult
    func setDetails(_ new: AccountDetails) -> Bool {
        do {
            try saveDetails(new)
            return true
        } catch {
            lastError = error.localizedDescription
            return false
        }
    }

    private func saveDetails(_ new: AccountDetails) throws {
        guard !areDetailsUnavailable else { throw StoreError.detailsUnavailable }
        if new.isEmpty {
            try detailsKeychain.delete(id: new.id, from: location)
            details[new.id] = nil
        } else {
            try detailsKeychain.save(new, to: location)
            details[new.id] = new
        }
    }

    enum StoreError: LocalizedError {
        case detailsUnavailable

        var errorDescription: String? {
            String(localized: "Recovery codes and websites could not be read from the Keychain. Try again after restarting the app.")
        }
    }

    func delete(_ id: UUID) {
        do {
            try keychain.delete(id: id, from: location)
            accounts.removeAll { $0.id == id }
            saveOrder()
            details[id] = nil
            // The account is gone either way; a leftover is cleared if the identifier is reused.
            try detailsKeychain.delete(id: id, from: location)
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// Accounts and passkeys together, in the order the user arranged them.
    var items: [KeyringItem] {
        let position = positions()
        let all = accounts.map(KeyringItem.account) + passkeys.map(KeyringItem.passkey)
        return all.sorted { lhs, rhs in
            let left = position[lhs.id.uuidString] ?? Int.max
            let right = position[rhs.id.uuidString] ?? Int.max
            return left != right ? left < right : lhs.createdAt < rhs.createdAt
        }
    }

    func move(fromOffsets source: IndexSet, toOffset destination: Int) {
        var arranged = items
        arranged.move(fromOffsets: source, toOffset: destination)
        saveOrder(arranged)
    }

    // MARK: Passkeys

    func addPasskey(_ passkey: Passkey) throws {
        try passkeyVault.save(passkey, syncEnabled: isSyncEnabled)
        passkeys.append(passkey)
        saveOrder()
    }

    func updatePasskey(_ id: UUID, title: String, cardColor: CardColor?) {
        guard let index = passkeys.firstIndex(where: { $0.id == id }) else { return }
        var passkey = passkeys[index]
        passkey.customTitle = title.isEmpty ? nil : title
        passkey.cardColor = cardColor
        do {
            try passkeyVault.save(passkey, syncEnabled: isSyncEnabled)
            passkeys[index] = passkey
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// Notes a sign-in. Only shown on the card, so a failure is not reported.
    func recordUse(of id: UUID, at date: Date = .now) {
        guard let index = passkeys.firstIndex(where: { $0.id == id }) else { return }
        passkeys[index].lastUsedAt = date
        try? passkeyVault.save(passkeys[index], syncEnabled: isSyncEnabled)
    }

    func deletePasskey(_ id: UUID) {
        guard let passkey = passkeys.first(where: { $0.id == id }) else { return }
        do {
            try passkeyVault.delete(passkey, syncEnabled: isSyncEnabled)
            passkeys.removeAll { $0.id == id }
            saveOrder()
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// Deletes every account here. With sync off, `includingICloud` also deletes
    /// the copies kept in iCloud Keychain, which removes them from other devices.
    func deleteAll(includingICloud: Bool = false) {
        do {
            try keychain.deleteAll(from: location)
            try detailsKeychain.deleteAll(from: location)
            if includingICloud, !isSyncEnabled {
                try keychain.deleteAll(from: .iCloud)
                try detailsKeychain.deleteAll(from: .iCloud)
            }
            // Device-only passkeys go too; synced ones as far as the accounts do.
            try passkeyVault.deleteAll(includingICloud: isSyncEnabled || includingICloud)
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
    /// Websites and recovery codes are added to the matching card in either case.
    func importAccounts(_ incoming: [OTPAccount], details incomingDetails: [AccountDetails] = []) -> ImportResult {
        // Checks against the Keychain, not a list that iCloud may have changed since,
        // so an imported account never overwrites an existing item in place.
        load()
        let extras = Dictionary(incomingDetails.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        var added = 0
        for var account in incoming {
            let originalID = account.id
            if let existing = accounts.first(where: { $0.generatesSameCodes(as: account) }) {
                account.id = existing.id
            } else {
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
            if let extra = extras[originalID] {
                do {
                    try saveDetails(details(for: account.id).merging(extra))
                } catch {
                    return ImportResult(added: added, error: error.localizedDescription)
                }
            }
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
        let localDetails = try detailsByID(in: .device)
        var syncedDetails = try detailsByID(in: .iCloud)
        var created: [UUID] = []
        var createdDetails: [UUID] = []
        var createdPasskeys: [UUID] = []
        var renamedIDs: [UUID: UUID] = [:]
        do {
            for var account in local {
                let localID = account.id
                var isMerged = false
                if let match = synced.first(where: { $0.generatesSameCodes(as: account) }) {
                    // The same key added separately on another device stays as one card.
                    if match.id != account.id {
                        renamedIDs[account.id] = match.id
                        account.id = match.id
                        isMerged = true
                    }
                } else if synced.contains(where: { $0.id == account.id }) {
                    // Same identifier but a different key: keep both instead of overwriting.
                    let newID = UUID()
                    renamedIDs[account.id] = newID
                    account.id = newID
                }
                if !isMerged {
                    let isNew = !synced.contains { $0.id == account.id }
                    try keychain.save(account, to: .iCloud)
                    if isNew {
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
        } catch {
            // Takes back what this attempt added, so the keys do not linger in iCloud.
            for id in created {
                try? keychain.delete(id: id, from: .iCloud)
            }
            for id in createdDetails {
                try? detailsKeychain.delete(id: id, from: .iCloud)
            }
            try? passkeyVault.deleteFromICloud(createdPasskeys)
            throw error
        }
        replaceInOrder(renamedIDs)
        saveSyncSetting(true)
        // Anything left here is a redundant copy, cleared again when sync is turned off.
        try? keychain.deleteAll(from: .device)
        try? detailsKeychain.deleteAll(from: .device)
        passkeyVault.removeSyncedCopiesFromDevice()
    }

    private func moveToDevice(removeFromICloud: Bool) throws {
        let synced = try keychain.loadAll(from: .iCloud)
        let syncedDetails = try detailsKeychain.loadAll(AccountDetails.self, from: .iCloud)
        // While sync is on, items on this device are only leftovers of an interrupted switch.
        try keychain.deleteAll(from: .device)
        try detailsKeychain.deleteAll(from: .device)
        for account in synced {
            try keychain.save(account, to: .device)
        }
        for extra in syncedDetails {
            try detailsKeychain.save(extra, to: .device)
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
            try passkeyVault.deleteFromICloud(syncedPasskeys.map(\.id))
        }
    }

    private func detailsByID(in location: KeychainStore.Location) throws -> [UUID: AccountDetails] {
        let loaded = try detailsKeychain.loadAll(AccountDetails.self, from: location)
        return Dictionary(loaded.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
    }

    private func insert(_ account: OTPAccount) throws {
        // Details left behind by a deleted account, possibly on a device running 1.0,
        // must not attach to a new one that reuses its identifier.
        if details[account.id] == nil, !areDetailsUnavailable {
            try detailsKeychain.delete(id: account.id, from: location)
        }
        try keychain.save(account, to: location)
        accounts.append(account)
        saveOrder()
        // An issuer that names its domain, such as "example.com", is suggested by
        // AutoFill right away; the card's edit screen shows and changes it.
        if let site = Website.domain(fromIssuer: account.issuer), !areDetailsUnavailable {
            var extra = details(for: account.id)
            if extra.websites.isEmpty {
                extra.websites = [site]
                try? saveDetails(extra)
            }
        }
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

    /// Saves the current arrangement, with cards added since at the end.
    private func saveOrder(_ arranged: [KeyringItem]? = nil) {
        order = (arranged ?? items).map(\.id.uuidString)
        defaults.set(order, forKey: Self.orderKey)
    }

    private func positions() -> [String: Int] {
        Dictionary(order.enumerated().map { ($0.element, $0.offset) }, uniquingKeysWith: { first, _ in first })
    }
}

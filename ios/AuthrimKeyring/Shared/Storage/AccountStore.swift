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
    /// Favorites and tags, by card; cards with neither are absent. Changed only
    /// through the methods in AccountStore+Meta.
    var meta: [UUID: ItemMeta] = [:]
    /// Set until the favorites and tags have been read, for the same reason.
    var isMetaUnavailable = true
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

    let keychain: AccountKeychain
    let detailsKeychain: KeychainStore
    let metaKeychain: KeychainStore
    let passkeyVault: PasskeyVault
    let defaults: UserDefaults
    /// Identifiers of every card in display order, as saved.
    private var order: [String] = []

    init(keychain: KeychainStore = KeychainStore(), defaults: UserDefaults = SharedDefaults.store) {
        self.keychain = AccountKeychain(base: keychain)
        detailsKeychain = KeychainStore(service: keychain.service + ".details")
        metaKeychain = KeychainStore(service: keychain.service + ".meta")
        passkeyVault = PasskeyVault(base: keychain)
        self.defaults = defaults
        isSyncEnabled = defaults.bool(forKey: Self.syncKey)
    }

    var location: KeychainStore.Location { isSyncEnabled ? .iCloud : .device }

    func load() {
        // Fails closed: only a successful read below clears these.
        areDetailsUnavailable = true
        isMetaUnavailable = true
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
            let (loaded, skippedAccounts) = try keychain.loadAllCountingSkipped(from: location)
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
            if let (loadedMeta, skippedMeta) = try? metaKeychain.loadAllCountingSkipped(ItemMeta.self, from: location) {
                meta = Dictionary(loadedMeta.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
                isMetaUnavailable = skippedMeta > 0
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
            account.kind = try latestKind(of: account)
            try keychain.save(account, to: location)
            accounts[index] = account
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// Hands out the next code of a counter-based account. The advanced counter is
    /// saved first, so no code is ever shown twice; nil when that fails.
    func nextCode(for id: UUID) -> String? {
        guard let index = accounts.firstIndex(where: { $0.id == id }) else { return nil }
        var account = accounts[index]
        do {
            guard case .hotp(let counter) = try latestKind(of: account), counter < .max else { return nil }
            account.kind = .hotp(counter: counter + 1)
            try keychain.save(account, to: location)
            accounts[index] = account
            return TOTPGenerator.hotp(secret: account.secret, counter: counter, algorithm: account.algorithm, digits: account.digits)
        } catch {
            lastError = error.localizedDescription
            return nil
        }
    }

    /// The kind with the counter as far as it has got, here or on another device
    /// since the list was read, so that saving never moves it back. Throws when the
    /// stored card cannot be read or is gone, rather than trust an older copy.
    func latestKind(of account: OTPAccount) throws -> OTPKind {
        guard case .hotp = account.kind else { return account.kind }
        guard let stored = try keychain.loadAll(from: location).first(where: { $0.id == account.id }) else {
            throw CounterError.unavailable
        }
        return Self.later(account.kind, stored.kind)
    }

    /// Whether adding `account` would move the counter of the same card here forward.
    func advancesCounter(_ account: OTPAccount) -> Bool {
        guard let existing = accounts.first(where: { $0.generatesSameCodes(as: account) }) else { return false }
        return Self.later(existing.kind, account.kind) != existing.kind
    }

    enum CounterError: LocalizedError {
        case unavailable

        var errorDescription: String? {
            String(localized: "This card could not be read from the Keychain. Try again after restarting the app.")
        }
    }

    /// Of two kinds of the same account, the one with the later counter.
    static func later(_ kind: OTPKind, _ other: OTPKind) -> OTPKind {
        if case .hotp(let counter) = kind, case .hotp(let otherCounter) = other, otherCounter > counter {
            return other
        }
        return kind
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
            deleteMeta(of: id)
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
            deleteMeta(of: id)
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
            try metaKeychain.deleteAll(from: location)
            if includingICloud, !isSyncEnabled {
                try keychain.deleteAll(from: .iCloud)
                try detailsKeychain.deleteAll(from: .iCloud)
                try metaKeychain.deleteAll(from: .iCloud)
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
    /// Websites, recovery codes, favorites and tags are added to the matching card
    /// in either case.
    func importAccounts(
        _ incoming: [OTPAccount],
        details incomingDetails: [AccountDetails] = [],
        meta incomingMeta: [ItemMeta] = []
    ) -> ImportResult {
        // Checks against the Keychain, not a list that iCloud may have changed since,
        // so an imported account never overwrites an existing item in place.
        load()
        let extras = Dictionary(incomingDetails.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        let notes = Dictionary(incomingMeta.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        var added = 0
        for var account in incoming {
            let originalID = account.id
            if let index = accounts.firstIndex(where: { $0.generatesSameCodes(as: account) }) {
                account.id = accounts[index].id
                // Codes the restored copy has used must not be handed out again.
                let later = Self.later(accounts[index].kind, account.kind)
                if later != accounts[index].kind {
                    var advanced = accounts[index]
                    advanced.kind = later
                    do {
                        try keychain.save(advanced, to: location)
                    } catch {
                        return ImportResult(added: added, error: error.localizedDescription)
                    }
                    accounts[index] = advanced
                }
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
            do {
                if let extra = extras[originalID] {
                    try saveDetails(details(for: account.id).merging(extra))
                }
                // Favorites and tags are a convenience, not worth failing the import for.
                if let note = notes[originalID], !isMetaUnavailable {
                    try saveMeta(meta(for: account.id).merging(note))
                }
            } catch {
                return ImportResult(added: added, error: error.localizedDescription)
            }
        }
        return ImportResult(added: added, error: nil)
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

    func saveSyncSetting(_ enabled: Bool) {
        isSyncEnabled = enabled
        defaults.set(enabled, forKey: Self.syncKey)
    }

    /// Keeps a card in place on this device when its identifier changes.
    func replaceInOrder(_ renamedIDs: [UUID: UUID]) {
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

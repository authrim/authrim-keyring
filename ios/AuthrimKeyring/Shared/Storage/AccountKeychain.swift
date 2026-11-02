import Foundation

/// Where accounts are kept in the Keychain.
///
/// Time-based accounts stay under the service versions 1.0 and 1.1 read, in the
/// format they wrote. Counter-based and Steam accounts go under a service of their
/// own: those versions would show them as time-based codes, and drop the counter
/// when saving one.
nonisolated struct AccountKeychain {
    let base: KeychainStore
    private let otherKinds: KeychainStore

    init(base: KeychainStore) {
        self.base = base
        otherKinds = KeychainStore(service: base.service + ".v2")
    }

    func loadAll(from location: KeychainStore.Location) throws -> [OTPAccount] {
        try loadAllCountingSkipped(from: location).items
    }

    func loadAllCountingSkipped(from location: KeychainStore.Location) throws -> (items: [OTPAccount], skipped: Int) {
        let timeBased = try base.loadAllCountingSkipped(OTPAccount.self, from: location)
        let others = try otherKinds.loadAllCountingSkipped(OTPAccount.self, from: location)
        return (timeBased.items + others.items, timeBased.skipped + others.skipped)
    }

    func save(_ account: OTPAccount, to location: KeychainStore.Location) throws {
        try store(for: account).save(account, to: location)
    }

    func delete(id: UUID, from location: KeychainStore.Location) throws {
        try base.delete(id: id, from: location)
        try otherKinds.delete(id: id, from: location)
    }

    func deleteAll(from location: KeychainStore.Location) throws {
        try base.deleteAll(from: location)
        try otherKinds.deleteAll(from: location)
    }

    private func store(for account: OTPAccount) -> KeychainStore {
        account.kind == .totp ? base : otherKinds
    }
}

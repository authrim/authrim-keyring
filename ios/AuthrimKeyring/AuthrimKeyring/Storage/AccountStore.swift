import Foundation
import Observation
import SwiftUI

@Observable
final class AccountStore {
    private static let orderKey = "accountOrder"

    private(set) var accounts: [OTPAccount] = []
    var lastError: String?

    private let keychain: KeychainStore
    private let defaults: UserDefaults

    init(keychain: KeychainStore = KeychainStore(), defaults: UserDefaults = .standard) {
        self.keychain = keychain
        self.defaults = defaults
    }

    func load() {
        do {
            let loaded = try keychain.loadAll()
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
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// True when an account with the same secret and parameters is already registered.
    func containsDuplicate(of candidate: OTPAccount) -> Bool {
        accounts.contains {
            $0.secret == candidate.secret
                && $0.algorithm == candidate.algorithm
                && $0.digits == candidate.digits
                && $0.period == candidate.period
        }
    }

    @discardableResult
    func add(_ account: OTPAccount) -> Bool {
        do {
            try keychain.save(account)
            accounts.append(account)
            saveOrder()
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
            try keychain.save(account)
            accounts[index] = account
        } catch {
            lastError = error.localizedDescription
        }
    }

    func delete(_ id: UUID) {
        do {
            try keychain.delete(id: id)
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

    func deleteAll() {
        do {
            try keychain.deleteAll()
            accounts = []
            defaults.removeObject(forKey: Self.orderKey)
        } catch {
            lastError = error.localizedDescription
        }
    }

    private func saveOrder() {
        defaults.set(accounts.map(\.id.uuidString), forKey: Self.orderKey)
    }
}

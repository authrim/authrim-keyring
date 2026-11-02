import Foundation
import Security

/// Persists each item (a TOTP account, or what goes with one) as its own
/// generic-password Keychain item, keyed by its identifier.
///
/// The app and its AutoFill extension list the app's own access group first in
/// `keychain-access-groups`, so both read and write the items version 1.0 saved.
///
/// Items live in one of two places. Device items use `WhenUnlockedThisDeviceOnly`,
/// so they are never synced nor restored onto another device. iCloud items are
/// synchronizable, which iCloud Keychain end-to-end encrypts and shares with the
/// user's other devices; the system does not allow `ThisDeviceOnly` for them.
struct KeychainStore {
    enum Location {
        case device
        case iCloud

        fileprivate var isSynchronizable: Bool { self == .iCloud }

        fileprivate var accessibility: CFString {
            switch self {
            case .device: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            case .iCloud: kSecAttrAccessibleWhenUnlocked
            }
        }
    }

    enum KeychainError: LocalizedError {
        case unexpectedStatus(OSStatus)

        var errorDescription: String? {
            switch self {
            case .unexpectedStatus(let status):
                let message = SecCopyErrorMessageString(status, nil) as String? ?? "\(status)"
                return String(localized: "Keychain error: \(message)")
            }
        }
    }

    var service = "com.authrim.keyring.totp"

    private func baseQuery(_ location: Location) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrSynchronizable as String: location.isSynchronizable,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    func loadAll(from location: Location) throws -> [OTPAccount] {
        try loadAll(OTPAccount.self, from: location)
    }

    func loadAll<Item: Decodable>(_ type: Item.Type, from location: Location) throws -> [Item] {
        try loadAllCountingSkipped(type, from: location).items
    }

    /// Also tells how many items could not be decoded, so a caller can tell a
    /// complete list from one missing what it could not read.
    func loadAllCountingSkipped<Item: Decodable>(
        _ type: Item.Type,
        from location: Location
    ) throws -> (items: [Item], skipped: Int) {
        var query = baseQuery(location)
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        query[kSecReturnData as String] = true

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return ([], 0) }
        guard status == errSecSuccess else { throw KeychainError.unexpectedStatus(status) }

        let items = result as? [Data] ?? []
        let decoder = JSONDecoder()
        // A corrupt item should not hide every other account.
        let decoded = items.compactMap { try? decoder.decode(Item.self, from: $0) }
        return (decoded, items.count - decoded.count)
    }

    func save<Item: Encodable & Identifiable>(_ item: Item, to location: Location) throws where Item.ID == UUID {
        let data = try JSONEncoder().encode(item)
        var query = baseQuery(location)
        query[kSecAttrAccount as String] = item.id.uuidString

        let update: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw KeychainError.unexpectedStatus(status) }

        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = location.accessibility
        let addStatus = SecItemAdd(query as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw KeychainError.unexpectedStatus(addStatus) }
    }

    func delete(id: UUID, from location: Location) throws {
        var query = baseQuery(location)
        query[kSecAttrAccount as String] = id.uuidString
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    func deleteAll(from location: Location) throws {
        let status = SecItemDelete(baseQuery(location) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }
}

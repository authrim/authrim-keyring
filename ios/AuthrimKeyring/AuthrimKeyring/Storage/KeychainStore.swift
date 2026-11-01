import Foundation
import Security

/// Persists each TOTP account as its own generic-password Keychain item.
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
        var query = baseQuery(location)
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        query[kSecReturnData as String] = true

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess else { throw KeychainError.unexpectedStatus(status) }

        let items = result as? [Data] ?? []
        let decoder = JSONDecoder()
        // A corrupt item should not hide every other account.
        return items.compactMap { try? decoder.decode(OTPAccount.self, from: $0) }
    }

    func save(_ account: OTPAccount, to location: Location) throws {
        let data = try JSONEncoder().encode(account)
        var query = baseQuery(location)
        query[kSecAttrAccount as String] = account.id.uuidString

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

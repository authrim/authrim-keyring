import Foundation
import Security

/// Persists each TOTP account as its own generic-password Keychain item.
///
/// Items use `WhenUnlockedThisDeviceOnly`, so secrets are never synced to iCloud
/// Keychain nor restored onto another device from a backup.
struct KeychainStore {
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

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    func loadAll() throws -> [OTPAccount] {
        var query = baseQuery
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

    func save(_ account: OTPAccount) throws {
        let data = try JSONEncoder().encode(account)
        var query = baseQuery
        query[kSecAttrAccount as String] = account.id.uuidString

        let update: [String: Any] = [kSecValueData as String: data]
        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw KeychainError.unexpectedStatus(status) }

        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let addStatus = SecItemAdd(query as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw KeychainError.unexpectedStatus(addStatus) }
    }

    func delete(id: UUID) throws {
        var query = baseQuery
        query[kSecAttrAccount as String] = id.uuidString
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }

    func deleteAll() throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }
}

import DeviceCheck
import Foundation
import Security

/// Apple App Attest as the wallet provider uses it. The attested key is created in the Secure Enclave
/// and cannot sign JWTs: it only vouches (attestation once, assertions after) for requests to the
/// wallet provider, which turns them into the JWTs an authorization server wants.
nonisolated protocol AppAttestService: Sendable {
    var isSupported: Bool { get }
    /// A new App Attest key; the identifier is the only handle to it.
    func generateKey() async throws -> String
    func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data
    func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data
}

/// The key identifier and whether the provider has accepted its attestation.
nonisolated struct AppAttestState: Codable, Equatable, Sendable {
    let keyID: String
    var registered: Bool
    /// While registering: the challenge in use and, once Apple answered, the attestation to send, so an
    /// interrupted registration resumes with the same key, challenge and hash (as Apple asks).
    var challenge: String? = nil
    var attestation: String? = nil
}

nonisolated protocol AppAttestStateStore: Sendable {
    func load() -> AppAttestState?
    func save(_ state: AppAttestState) throws
    func clear()
}

nonisolated struct SystemAppAttestService: AppAttestService {
    private var service: DCAppAttestService { DCAppAttestService.shared }
    var isSupported: Bool { service.isSupported }

    func generateKey() async throws -> String { try await service.generateKey() }
    func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data {
        try await service.attestKey(keyID, clientDataHash: clientDataHash)
    }
    func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data {
        try await service.generateAssertion(keyID, clientDataHash: clientDataHash)
    }
}

/// The key identifier lives in the Keychain, this device only: App Attest keys do not survive a
/// restore or a move to another device, and neither may their identifier.
nonisolated struct KeychainAppAttestState: AppAttestStateStore {
    private static let service = "com.authrim.keyring.app-attest"
    private static let account = "provider-key"

    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: Self.service, kSecAttrAccount as String: Self.account]
    }

    func load() -> AppAttestState? {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(request as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return try? JSONDecoder().decode(AppAttestState.self, from: data)
    }

    /// Updates in place: a failed write leaves the earlier state, which an interrupted registration needs.
    func save(_ state: AppAttestState) throws {
        let data = try JSONEncoder().encode(state)
        let update = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else {
            throw WalletError.storage("The App Attest key identifier could not be saved.")
        }
        var item = query
        item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else {
            throw WalletError.storage("The App Attest key identifier could not be saved.")
        }
    }

    func clear() { SecItemDelete(query as CFDictionary) }
}

#if DEBUG
/// For debug builds against a debug provider that verifies nothing (`WalletProviderKind` =
/// `debugUnattested`). Not compiled into release builds.
nonisolated struct DebugUnattestedAppAttest: AppAttestService {
    var isSupported: Bool { true }
    func generateKey() async throws -> String { "debug-unattested-key" }
    func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data { Data("debug-attestation".utf8) }
    func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data { Data("debug-assertion".utf8) }
}
#endif

import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// A credential's own holder key: it signs the proof now and lives as long as the credential.
nonisolated protocol HolderSigning: Sendable {
    var tag: String { get }
    var publicJWK: PublicJWK { get }
    /// ES256 signature over `message`, raw `r || s` (64 bytes). May ask for Face ID / passcode.
    func sign(_ message: Data) throws -> Data
}

/// Creates, loads and deletes holder keys.
///
/// The key is a P-256 key generated inside the Secure Enclave (`kSecAttrTokenIDSecureEnclave`), so its
/// private part is never exportable. Using it needs `.userPresence` (Face ID or passcode), and it is
/// only available while the device is unlocked, on this device (`WhenUnlockedThisDeviceOnly`).
///
/// SIMULATOR FALLBACK: the iOS Simulator has no Secure Enclave. Only in a DEBUG build running on the
/// simulator (`#if targetEnvironment(simulator) && DEBUG`) the key is always instead a software P-256 key kept
/// in the Keychain, with no user-presence check. Every other build (including every device build and any
/// Release build) fails with `WalletError.keyUnavailable` when the Secure Enclave is missing.
nonisolated enum HolderKey {
    static let tagPrefix = "com.authrim.keyring.vc.holder."
    static let softwareService = "com.authrim.keyring.vc.holder.software"

    static func makeTag() -> String { tagPrefix + UUID().uuidString }

    static func create(tag: String) throws -> any HolderSigning {
        #if targetEnvironment(simulator) && DEBUG
        // The simulator reports a Secure Enclave but cannot create user-presence keys in it.
        return try SoftwareKey.create(tag: tag)
        #else
        guard SecureEnclave.isAvailable else { throw WalletError.keyUnavailable("This device has no Secure Enclave.") }
        return try SecureEnclaveKey.create(tag: tag)
        #endif
    }

    /// Deletes the key under `tag`. Succeeds when there is none.
    static func delete(tag: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw WalletError.keyUnavailable("The key could not be deleted (\(status)).")
        }
        #if targetEnvironment(simulator) && DEBUG
        try SoftwareKey.delete(tag: tag)
        #endif
    }
}

// MARK: - Secure Enclave

nonisolated struct SecureEnclaveKey: HolderSigning {
    let tag: String
    let publicJWK: PublicJWK

    static func create(tag: String) throws -> SecureEnclaveKey {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], &error)
        else { throw WalletError.keyUnavailable("Access control could not be created.") }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Data(tag.utf8),
                kSecAttrAccessControl as String: access,
            ] as [String: Any],
        ]
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw WalletError.keyUnavailable("The Secure Enclave key could not be created.")
        }
        return try SecureEnclaveKey(tag: tag, privateKey: privateKey)
    }

    private init(tag: String, privateKey: SecKey) throws {
        guard let publicKey = SecKeyCopyPublicKey(privateKey),
              let external = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?,
              let jwk = PublicJWK(x963: external)
        else { throw WalletError.keyUnavailable("The public key could not be read.") }
        self.tag = tag
        publicJWK = jwk
    }

    func sign(_ message: Data) throws -> Data {
        let context = LAContext()
        context.localizedReason = String(localized: "Create the proof for the credential request")
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(tag.utf8),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess, let item else {
            throw WalletError.keyUnavailable("The key was not found.")
        }
        var error: Unmanaged<CFError>?
        guard let der = SecKeyCreateSignature(
            item as! SecKey, .ecdsaSignatureMessageX962SHA256, message as CFData, &error) as Data?
        else {
            let code = (error?.takeRetainedValue()).map { CFErrorGetCode($0) } ?? 0
            throw WalletError.keyUnavailable(code == Int(errSecUserCanceled) ? "Cancelled." : "Signing failed (\(code)).")
        }
        guard let raw = DERSignature.rawES256(der) else { throw WalletError.keyUnavailable("The signature was malformed.") }
        return raw
    }
}

// MARK: - DER -> JOSE

nonisolated enum DERSignature {
    /// Converts an ASN.1 `SEQUENCE { INTEGER r, INTEGER s }` into 64 bytes `r || s`.
    static func rawES256(_ der: Data) -> Data? {
        let bytes = [UInt8](der)
        var index = 0
        func length() -> Int? {
            guard index < bytes.count else { return nil }
            let first = bytes[index]
            index += 1
            if first < 0x80 { return Int(first) }
            guard first == 0x81, index < bytes.count else { return nil }
            index += 1
            return Int(bytes[index - 1])
        }
        func integer() -> [UInt8]? {
            guard index < bytes.count, bytes[index] == 0x02 else { return nil }
            index += 1
            guard let size = length(), size > 0, index + size <= bytes.count else { return nil }
            var value = Array(bytes[index..<index + size])
            index += size
            while value.count > 32, value.first == 0 { value.removeFirst() }
            guard value.count <= 32 else { return nil }
            return [UInt8](repeating: 0, count: 32 - value.count) + value
        }
        guard index < bytes.count, bytes[index] == 0x30 else { return nil }
        index += 1
        guard let total = length(), index + total == bytes.count,
              let r = integer(), let s = integer(), index == bytes.count else { return nil }
        return Data(r + s)
    }
}

// MARK: - Simulator-only software key

#if targetEnvironment(simulator) && DEBUG
/// Debug/simulator stand-in for the Secure Enclave (see `HolderKey`). Never compiled into device or Release builds.
nonisolated struct SoftwareKey: HolderSigning {
    let tag: String
    let publicJWK: PublicJWK
    private let key: P256.Signing.PrivateKey

    static func create(tag: String) throws -> SoftwareKey {
        let key = P256.Signing.PrivateKey()
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: HolderKey.softwareService,
            kSecAttrAccount as String: tag,
            kSecValueData as String: key.rawRepresentation,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: true,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw WalletError.keyUnavailable("The software key could not be stored (\(status)).") }
        return try SoftwareKey(tag: tag, key: key)
    }

    private init(tag: String, key: P256.Signing.PrivateKey) throws {
        guard let jwk = PublicJWK(x963: key.publicKey.x963Representation) else {
            throw WalletError.keyUnavailable("The public key could not be read.")
        }
        self.tag = tag
        self.key = key
        publicJWK = jwk
    }

    func sign(_ message: Data) throws -> Data {
        do { return try key.signature(for: message).rawRepresentation } catch {
            throw WalletError.keyUnavailable("Signing failed.")
        }
    }

    static func delete(tag: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: HolderKey.softwareService,
            kSecAttrAccount as String: tag,
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: true,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw WalletError.keyUnavailable("The software key could not be deleted (\(status)).")
        }
    }
}
#endif

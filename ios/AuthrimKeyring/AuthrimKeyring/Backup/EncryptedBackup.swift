import CommonCrypto
import CryptoKit
import Foundation
import Security

/// Password-protected backup file of every account.
///
/// The accounts are encoded as JSON and sealed with AES-256-GCM. The key is derived
/// from the password with PBKDF2-HMAC-SHA256 and a random salt. The file header is
/// bound to the ciphertext as associated data, so its parameters cannot be swapped.
///
/// Both directions are slow on purpose (key derivation), so call them off the main actor.
nonisolated enum EncryptedBackup {
    static let minimumPasswordLength = 8

    private static let format = "com.authrim.keyring.backup"
    private static let version = 1
    private static let kdfName = "PBKDF2-HMAC-SHA256"
    private static let cipherName = "AES-256-GCM"
    private static let iterations = 600_000
    /// Bounds accepted on import, so a crafted file cannot stall the app.
    private static let acceptedIterations = 100_000...10_000_000
    static let maximumFileSize = 5 * 1024 * 1024
    static let maximumAccounts = 1_000

    enum BackupError: LocalizedError, Equatable {
        case notABackup
        case newerVersion
        case wrongPassword
        case damaged
        case tooLarge
        case tooManyAccounts

        var errorDescription: String? {
            switch self {
            case .notABackup:
                String(localized: "This file is not a Keyring backup.")
            case .newerVersion:
                String(localized: "This backup was made by a newer version of Keyring. Update the app and try again.")
            case .wrongPassword:
                String(localized: "The password is incorrect, or the file is damaged.")
            case .damaged:
                String(localized: "The backup file is damaged.")
            case .tooLarge:
                String(localized: "The file is too large to be a Keyring backup.")
            case .tooManyAccounts:
                String(localized: "A backup can hold up to \(EncryptedBackup.maximumAccounts) accounts.")
            }
        }
    }

    private struct Envelope: Codable {
        struct KeyDerivation: Codable {
            var algorithm: String
            var iterations: Int
            var salt: Data
        }

        var format: String
        var version: Int
        var kdf: KeyDerivation
        var cipher: String
        /// Nonce, ciphertext and tag of the sealed `Payload`.
        var sealed: Data

        var associatedData: Data {
            let header = [format, String(version), kdf.algorithm, String(kdf.iterations), kdf.salt.base64EncodedString(), cipher]
            return Data(header.joined(separator: "|").utf8)
        }
    }

    /// What a backup holds.
    struct Contents: Sendable {
        var accounts: [OTPAccount]
        /// Websites and recovery codes, matched to `accounts` by identifier.
        var details: [AccountDetails] = []
    }

    // `details` was added in 1.1 without changing the version: 1.0 ignores keys it
    // does not know, so it can still open these files and restore the accounts.
    private struct Payload: Codable {
        var exportedAt: Date
        var accounts: [OTPAccount]
        var details: [AccountDetails]?
    }

    static func seal(_ contents: Contents, password: String, now: Date = .now) throws -> Data {
        let accounts = contents.accounts
        // Never hand out a file that `open` would refuse.
        guard accounts.count <= maximumAccounts else { throw BackupError.tooManyAccounts }
        let salt = try randomBytes(count: 16)
        var envelope = Envelope(
            format: format,
            version: version,
            kdf: .init(algorithm: kdfName, iterations: iterations, salt: salt),
            cipher: cipherName,
            sealed: Data()
        )
        let key = try deriveKey(password: password, salt: salt, iterations: iterations)
        let accountIDs = Set(accounts.map(\.id))
        let details = contents.details.filter { accountIDs.contains($0.id) && !$0.isEmpty }
        let payload = Payload(exportedAt: now, accounts: accounts, details: details.isEmpty ? nil : details)
        let plaintext = try makeEncoder().encode(payload)
        let box = try AES.GCM.seal(plaintext, using: key, authenticating: envelope.associatedData)
        guard let combined = box.combined else { throw BackupError.damaged }
        envelope.sealed = combined
        let file = try makeEncoder().encode(envelope)
        guard file.count <= maximumFileSize else { throw BackupError.tooManyAccounts }
        return file
    }

    static func open(_ file: Data, password: String) throws -> Contents {
        guard file.count <= maximumFileSize else { throw BackupError.tooLarge }
        guard let envelope = try? JSONDecoder().decode(Envelope.self, from: file),
              envelope.format == format
        else { throw BackupError.notABackup }
        guard envelope.version <= version else { throw BackupError.newerVersion }
        guard envelope.version == version,
              envelope.kdf.algorithm == kdfName,
              envelope.cipher == cipherName,
              acceptedIterations.contains(envelope.kdf.iterations),
              envelope.kdf.salt.count >= 16
        else { throw BackupError.damaged }

        let key = try deriveKey(password: password, salt: envelope.kdf.salt, iterations: envelope.kdf.iterations)
        let plaintext: Data
        do {
            let box = try AES.GCM.SealedBox(combined: envelope.sealed)
            plaintext = try AES.GCM.open(box, using: key, authenticating: envelope.associatedData)
        } catch {
            throw BackupError.wrongPassword
        }

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        guard let payload = try? decoder.decode(Payload.self, from: plaintext),
              payload.accounts.count <= maximumAccounts,
              payload.accounts.allSatisfy(\.isSupported),
              (payload.details?.count ?? 0) <= maximumAccounts
        else { throw BackupError.damaged }
        // Each set of details must belong to exactly one account, or codes could
        // end up on the wrong card.
        let accountIDs = Set(payload.accounts.map(\.id))
        let detailIDs = (payload.details ?? []).map(\.id)
        guard accountIDs.count == payload.accounts.count,
              Set(detailIDs).count == detailIDs.count,
              detailIDs.allSatisfy(accountIDs.contains)
        else { throw BackupError.damaged }
        let details = (payload.details ?? []).map { extra in
            var extra = extra
            extra.recoveryCodes = Array(extra.recoveryCodes.prefix(AccountDetails.maximumRecoveryCodes))
            return extra
        }
        return Contents(accounts: payload.accounts, details: details)
    }

    private static func makeEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }

    private static func deriveKey(password: String, salt: Data, iterations: Int) throws -> SymmetricKey {
        // Normalized so the same password typed on another device still matches.
        let passwordBytes = Array(password.precomposedStringWithCanonicalMapping.utf8)
        guard !passwordBytes.isEmpty else { throw BackupError.wrongPassword }
        var derived = [UInt8](repeating: 0, count: 32)
        let status = salt.withUnsafeBytes { saltBytes in
            passwordBytes.withUnsafeBufferPointer { passwordBuffer in
                passwordBuffer.withMemoryRebound(to: CChar.self) { passwordChars in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordChars.baseAddress, passwordChars.count,
                        saltBytes.bindMemory(to: UInt8.self).baseAddress, saltBytes.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(iterations),
                        &derived, derived.count
                    )
                }
            }
        }
        guard status == kCCSuccess else { throw BackupError.damaged }
        return SymmetricKey(data: derived)
    }

    private static func randomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
            throw BackupError.damaged
        }
        return Data(bytes)
    }
}

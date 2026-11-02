import AuthenticationServices
import CryptoKit
import Foundation

/// Converts between Keyring's cards and the FIDO Credential Exchange Format, in
/// which iOS 26 and later move credentials from one app to another.
@available(iOS 26, *)
nonisolated enum CredentialExchange {
    /// The exporting extension; the app has only the one.
    static let extensionBundleIdentifier = "com.authrim.keyring.autofill"
    /// Marks the note that carries a card's recovery codes, one per line. Not
    /// localized, so an export read on a device in another language is still recognized.
    static let recoveryCodesLabel = "Recovery Codes"

    // MARK: Import

    /// The one-time codes and passkeys in another app's export. Anything else,
    /// such as passwords, is only counted.
    static func read(
        _ data: ASExportedCredentialData,
        isDeviceOnly: (String) -> Bool = { PasskeySyncRules.isDeviceOnly($0) }
    ) throws(ImportError) -> ImportedAccounts {
        var result = ImportedAccounts()
        for item in data.accounts.flatMap(\.items) {
            let websites = websites(in: item.scope)
            // Recovery codes go with the item's one-time code, wherever the note is.
            var codes = AccountDetails(id: UUID())
            for case .note(let note) in item.credentials where note.content.label == recoveryCodesLabel {
                codes.addRecoveryCodes(from: note.content.value)
            }
            for credential in item.credentials {
                switch credential {
                case .totp(let totp):
                    let account = OTPAccount(
                        issuer: totp.issuer.flatMap { $0.isEmpty ? nil : $0 } ?? item.title,
                        accountName: totp.userName ?? "",
                        secret: totp.secret,
                        algorithm: algorithm(totp.algorithm),
                        digits: Int(totp.digits),
                        period: Int(totp.period),
                        createdAt: item.created ?? .now
                    )
                    let before = result.accounts.count
                    result.add(account, label: [account.issuer, account.accountName].filter { !$0.isEmpty }.joined(separator: " – "))
                    guard result.accounts.count > before else { continue }
                    let extra = AccountDetails(id: account.id, websites: websites, recoveryCodes: codes.recoveryCodes)
                    if !extra.isEmpty {
                        result.details.append(extra)
                    }
                    // Only the first code of the item gets them.
                    codes.recoveryCodes = []
                    note(item, for: account.id, in: &result)
                case .passkey(let exported):
                    guard let passkey = passkey(exported, in: item, isDeviceOnly: isDeviceOnly) else {
                        result.skip(exported.relyingPartyIdentifier, reason: String(localized: "This kind of passkey is not supported."))
                        continue
                    }
                    result.passkeys.append(passkey)
                    note(item, for: passkey.id, in: &result)
                case .note(let note) where note.content.label == recoveryCodesLabel:
                    // Read above.
                    continue
                default:
                    result.otherCount += 1
                }
            }
            guard result.accounts.count + result.passkeys.count + result.skipped.count <= ImportedAccounts.maximumEntries else {
                throw .tooLarge
            }
        }
        return result
    }

    private static func passkey(
        _ exported: ASImportableCredential.Passkey,
        in item: ASImportableItem,
        isDeviceOnly: (String) -> Bool
    ) -> Passkey? {
        // Keyring signs with P-256 only; the key comes as PKCS #8.
        guard let key = try? P256.Signing.PrivateKey(derRepresentation: exported.key),
              !exported.relyingPartyIdentifier.isEmpty,
              !exported.credentialID.isEmpty
        else { return nil }
        let title = item.title.trimmingCharacters(in: .whitespaces)
        return Passkey(
            id: UUID(),
            credentialID: exported.credentialID,
            relyingParty: exported.relyingPartyIdentifier,
            userName: exported.userName.isEmpty ? exported.userDisplayName : exported.userName,
            userHandle: exported.userHandle,
            createdAt: item.created ?? .now,
            // The user's rule for the site decides, as for a passkey saved here.
            isBackupEligible: !isDeviceOnly(exported.relyingPartyIdentifier),
            isInSecureEnclave: false,
            privateKey: key.rawRepresentation,
            customTitle: title.isEmpty || title == exported.relyingPartyIdentifier ? nil : title
        )
    }

    private static func note(_ item: ASImportableItem, for id: UUID, in result: inout ImportedAccounts) {
        let note = ItemMeta(id: id, isFavorite: item.favorite, tags: ItemMeta.cleaned(item.tags))
        if !note.isEmpty {
            result.meta.append(note)
        }
    }

    private static func websites(in scope: ASImportableCredentialScope?) -> [String] {
        var result: [String] = []
        for url in scope?.urls ?? [] where ["http", "https"].contains(url.scheme?.lowercased()) {
            if let site = url.host().flatMap(Website.normalized), !result.contains(site), result.count < Website.maximumPerAccount {
                result.append(site)
            }
        }
        return result
    }

    private static func algorithm(_ algorithm: ASImportableCredential.TOTP.Algorithm) -> OTPAlgorithm {
        switch algorithm {
        case .sha256: .sha256
        case .sha512: .sha512
        default: .sha1
        }
    }

    // MARK: Export

    struct Export {
        var data: ASExportedCredentialData
        var exportedCount: Int
        /// Cards the format cannot carry or that must stay on this device.
        var leftOutCount: Int
    }

    /// Everything that may leave the device: time-based accounts with their
    /// websites and unused recovery codes, and passkeys that are allowed to sync.
    static func export(
        accounts: [OTPAccount],
        passkeys: [Passkey],
        details: [UUID: AccountDetails],
        meta: [UUID: ItemMeta],
        formatVersion: ASExportedCredentialData.FormatVersion,
        now: Date = .now
    ) -> Export {
        var items: [ASImportableItem] = []
        var leftOut = 0
        for account in accounts {
            // The format has no counter-based or Steam codes.
            guard account.kind == .totp else {
                leftOut += 1
                continue
            }
            let extra = details[account.id]
            var credentials: [ASImportableCredential] = [.totp(.init(
                secret: account.secret,
                period: UInt16(account.period),
                digits: UInt16(account.digits),
                userName: account.accountName.isEmpty ? nil : account.accountName,
                algorithm: algorithm(account.algorithm),
                issuer: account.issuer.isEmpty ? nil : account.issuer
            ))]
            let unused = extra?.recoveryCodes.filter { $0.usedAt == nil }.map(\.code) ?? []
            if !unused.isEmpty {
                let text = unused.joined(separator: "\n")
                credentials.append(.note(.init(content: .init(id: nil, fieldType: .concealedString, value: text, label: recoveryCodesLabel))))
            }
            items.append(item(
                id: account.id,
                created: account.createdAt,
                title: account.displayTitle,
                subtitle: account.displaySubtitle,
                sites: extra?.websites ?? [],
                meta: meta[account.id],
                credentials: credentials
            ))
        }
        for passkey in passkeys {
            // A device-only passkey was meant never to leave; in the Secure Enclave
            // it cannot.
            guard passkey.isBackupEligible, !passkey.isInSecureEnclave,
                  let key = try? P256.Signing.PrivateKey(rawRepresentation: passkey.privateKey)
            else {
                leftOut += 1
                continue
            }
            let credential = ASImportableCredential.Passkey(
                credentialID: passkey.credentialID,
                relyingPartyIdentifier: passkey.relyingParty,
                userName: passkey.userName,
                userDisplayName: passkey.userName,
                userHandle: passkey.userHandle,
                key: key.derRepresentation
            )
            items.append(item(
                id: passkey.id,
                created: passkey.createdAt,
                title: passkey.displayTitle,
                subtitle: passkey.displaySubtitle,
                sites: [passkey.relyingParty],
                meta: meta[passkey.id],
                credentials: [.passkey(credential)]
            ))
        }
        let account = ASImportableAccount(
            id: withUnsafeBytes(of: UUID().uuid) { Data($0) },
            userName: "",
            email: "",
            collections: [],
            items: items
        )
        let data = ASExportedCredentialData(
            accounts: [account],
            formatVersion: formatVersion,
            exporterRelyingPartyIdentifier: "authrim.com",
            exporterDisplayName: "Authrim Keyring",
            timestamp: now
        )
        return Export(data: data, exportedCount: items.count, leftOutCount: leftOut)
    }

    private static func item(
        id: UUID,
        created: Date,
        title: String,
        subtitle: String?,
        sites: [String],
        meta: ItemMeta?,
        credentials: [ASImportableCredential]
    ) -> ASImportableItem {
        let urls = sites.compactMap { URL(string: "https://" + $0) }
        return ASImportableItem(
            id: withUnsafeBytes(of: id.uuid) { Data($0) },
            created: created,
            lastModified: created,
            title: title,
            subtitle: subtitle,
            favorite: meta?.isFavorite ?? false,
            scope: urls.isEmpty ? nil : ASImportableCredentialScope(urls: urls),
            credentials: credentials,
            tags: meta?.tags ?? []
        )
    }

    private static func algorithm(_ algorithm: OTPAlgorithm) -> ASImportableCredential.TOTP.Algorithm {
        switch algorithm {
        case .sha1: .sha1
        case .sha256: .sha256
        case .sha512: .sha512
        }
    }
}

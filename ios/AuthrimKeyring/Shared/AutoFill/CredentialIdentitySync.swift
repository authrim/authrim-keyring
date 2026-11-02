import AuthenticationServices
import Foundation
import OSLog

/// Tells the system what Keyring can fill in, so AutoFill can suggest it above the
/// keyboard. Only names, sites and passkey identifiers are shared, never a secret.
nonisolated enum CredentialIdentitySync {
    /// A card's code offered on one site.
    struct OneTimeCode: Hashable, Sendable {
        var accountID: UUID
        var site: String
        var label: String
    }

    struct PasskeyEntry: Hashable, Sendable {
        var id: UUID
        var relyingParty: String
        var userName: String
        var credentialID: Data
        var userHandle: Data
    }

    struct Identities: Hashable, Sendable {
        var codes: [OneTimeCode] = []
        var passkeys: [PasskeyEntry] = []
    }

    static func identities(accounts: [OTPAccount], details: [UUID: AccountDetails], passkeys: [Passkey]) -> Identities {
        Identities(
            codes: accounts.flatMap { account in
                (details[account.id]?.websites ?? []).map { site in
                    OneTimeCode(accountID: account.id, site: site, label: account.autoFillLabel)
                }
            },
            passkeys: passkeys.map {
                PasskeyEntry(
                    id: $0.id,
                    relyingParty: $0.relyingParty,
                    userName: $0.userName,
                    credentialID: $0.credentialID,
                    userHandle: $0.userHandle
                )
            }
        )
    }

    /// Replaces everything registered before, so removed cards and sites disappear.
    static func replace(with identities: Identities) async {
        // Not gated on `state().isEnabled`, which can lag behind the Settings switch;
        // registering while AutoFill is off fails harmlessly and is retried on the next change.
        let store = ASCredentialIdentityStore.shared
        var registered: [any ASCredentialIdentity] = identities.passkeys.map {
            ASPasskeyCredentialIdentity(
                relyingPartyIdentifier: $0.relyingParty,
                userName: $0.userName,
                credentialID: $0.credentialID,
                userHandle: $0.userHandle,
                recordIdentifier: $0.id.uuidString
            )
        }
        if #available(iOS 18, *) {
            registered += identities.codes.map { entry in
                ASOneTimeCodeCredentialIdentity(
                    serviceIdentifier: ASCredentialServiceIdentifier(identifier: entry.site, type: .domain),
                    label: entry.label,
                    recordIdentifier: entry.accountID.uuidString
                )
            }
        }
        // A failure only means fewer suggestions; choosing Keyring still lists everything.
        do {
            try await store.replaceCredentialIdentities(registered)
            logger.info("Registered \(registered.count) AutoFill identities")
        } catch {
            logger.error("Could not register AutoFill identities: \(error.localizedDescription)")
        }
    }

    private static let logger = Logger(subsystem: "com.authrim.keyring", category: "AutoFill")
}

extension OTPAccount {
    /// How the card is named in AutoFill suggestions.
    nonisolated var autoFillLabel: String {
        displaySubtitle.map { "\(displayTitle) (\($0))" } ?? displayTitle
    }
}

import Foundation

/// Accounts read from another app's export, and the entries that could not be used.
nonisolated struct ImportedAccounts: Sendable {
    struct Skipped: Hashable, Sendable {
        var name: String
        var reason: String
    }

    var accounts: [OTPAccount] = []
    var skipped: [Skipped] = []

    static let maximumEntries = 1_000

    mutating func append(contentsOf other: ImportedAccounts) {
        accounts += other.accounts
        skipped += other.skipped
    }

    /// Keeps a usable account, or records why it cannot be used.
    mutating func add(_ account: OTPAccount, label: String) {
        if let reason = Self.unsupportedReason(account) {
            skipped.append(Skipped(name: label, reason: reason))
        } else {
            accounts.append(account)
        }
    }

    mutating func skip(_ label: String, reason: String) {
        skipped.append(Skipped(name: label, reason: reason))
    }

    private static func unsupportedReason(_ account: OTPAccount) -> String? {
        if account.secret.isEmpty {
            return String(localized: "No secret key")
        }
        if !OTPAccount.supportedDigits.contains(account.digits) {
            return String(localized: "\(account.digits)-digit codes are not supported.")
        }
        if !OTPAccount.supportedPeriods.contains(account.period) {
            return String(localized: "A period of \(account.period) seconds is not supported.")
        }
        return nil
    }
}

/// Why a whole file or code could not be read.
nonisolated enum ImportError: LocalizedError, Equatable {
    case unrecognized
    case encrypted(app: String)
    /// Codes from more than one Google Authenticator transfer.
    case mixedTransfers
    case incompleteTransfer(scanned: Int, total: Int)
    case tooLarge
    case damaged

    var errorDescription: String? {
        switch self {
        case .unrecognized:
            String(localized: "This file is not an export Keyring can read.")
        case .encrypted(let app):
            String(localized: "This \(app) export is encrypted. Export it again without encryption, import it, then delete the file.")
        case .mixedTransfers:
            String(localized: "These codes come from different transfers. Start over and use the codes of a single transfer.")
        case .incompleteTransfer(let scanned, let total):
            String(localized: "Only \(scanned) of the \(total) codes of this Google Authenticator transfer were found.")
        case .tooLarge:
            String(localized: "The file is too large.")
        case .damaged:
            String(localized: "The export could not be read. It may be damaged.")
        }
    }
}

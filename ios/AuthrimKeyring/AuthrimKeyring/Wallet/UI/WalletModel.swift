import Foundation
import Observation

/// An offer that arrived from the scanner or a link and is waiting to be shown.
struct IncomingOffer: Identifiable, Hashable {
    let id = UUID()
    let text: String
}

/// What the wallet screens share: the credentials on this device and the offer on its way in.
/// It only knows the protocols, so previews and tests can supply their own services.
@Observable
final class WalletModel {
    let issuance: any CredentialIssuanceService
    private let store: any CredentialStore

    /// Newest first.
    private(set) var credentials: [StoredCredential] = []
    /// An offer opened from a link, shown once the app is unlocked.
    var incomingOffer: IncomingOffer?
    /// The credential whose detail is open.
    var detail: StoredCredential?
    var lastError: String?
    /// Set while the stored credentials cannot be read; Home offers a retry. Cleared by the next successful load.
    var loadError: String?

    init(issuance: any CredentialIssuanceService, store: any CredentialStore) {
        self.issuance = issuance
        self.store = store
    }

    func load() {
        do {
            credentials = try store.loadAll().sorted { $0.issuedAt > $1.issuedAt }
            loadError = nil
        } catch {
            loadError = String(localized: "The credentials could not be read.")
        }
    }

    /// Deletes the credential and its key. Returns false when that failed.
    @discardableResult
    func remove(_ credential: StoredCredential) -> Bool {
        do {
            try store.delete(credential)
        } catch {
            lastError = String(localized: "The credential could not be removed.")
            return false
        }
        credentials.removeAll { $0.id == credential.id }
        return true
    }

    /// Takes an `openid-credential-offer://` link opened from outside the app.
    func handle(url: URL) {
        guard CredentialOfferLink.isOffer(url.absoluteString) else { return }
        incomingOffer = IncomingOffer(text: url.absoluteString)
    }
}

enum CredentialOfferLink {
    static let scheme = "openid-credential-offer"

    /// Whether scanned or opened text is a credential offer link (the scheme is case-insensitive).
    static func isOffer(_ text: String) -> Bool {
        text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().hasPrefix(scheme + ":")
    }
}

extension URL {
    /// The part of an issuer address the user should compare: host, and port if not the default.
    var walletHost: String {
        let host = host(percentEncoded: false) ?? absoluteString
        guard let port else { return host }
        return "\(host):\(port)"
    }
}

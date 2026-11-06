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
    let presentation: any PresentationService
    private let store: any CredentialStore
    private let trustedIssuers: [TrustedIssuer]

    /// Newest first.
    private(set) var credentials: [StoredCredential] = []
    /// An offer opened from a link, shown once the app is unlocked.
    var incomingOffer: IncomingOffer?
    /// A presentation request (`openid4vp://`) opened from a link, shown once the app is unlocked.
    var incomingPresentation: IncomingOffer?
    /// The credential whose detail is open.
    var detail: StoredCredential?
    var lastError: String?
    /// Set while the stored credentials cannot be read; Home offers a retry. Cleared by the next successful load.
    var loadError: String?

    init(
        issuance: any CredentialIssuanceService, store: any CredentialStore,
        presentation: any PresentationService = OpenID4VPClient(),
        trustedIssuers: [TrustedIssuer] = TrustedIssuer.all
    ) {
        self.issuance = issuance
        self.presentation = presentation
        self.store = store
        self.trustedIssuers = trustedIssuers
    }

    func trust(for issuer: URL) -> IssuerTrust {
        IssuerTrust.of(issuer, trusted: trustedIssuers, credentials: credentials)
    }

    /// Records that the admin console shows the same confirmation code. Returns false when that failed.
    @discardableResult
    func confirm(_ credential: StoredCredential) -> Bool {
        var confirmed = credential
        confirmed.confirmedAt = .now
        do {
            try store.save(confirmed)
        } catch {
            lastError = String(localized: "The confirmation could not be saved.")
            return false
        }
        // Added when missing too: the list is stale if reading it failed right after the credential was issued.
        credentials.removeAll { $0.id == credential.id }
        credentials.append(confirmed)
        credentials.sort { $0.issuedAt > $1.issuedAt }
        return true
    }

    /// Records that the admin console accepted the key of `credential` as a second factor. Every
    /// credential sharing that key is the same factor. A failed save only loses the hint.
    func markSecondFactor(_ credential: StoredCredential) {
        let at = Date.now
        for index in credentials.indices where credentials[index].keyTag == credential.keyTag {
            guard credentials[index].secondFactorRegisteredAt == nil else { continue }
            var marked = credentials[index]
            marked.secondFactorRegisteredAt = at
            if (try? store.save(marked)) != nil { credentials[index] = marked }
        }
    }

    /// Whether deleting `credential` also deletes its holder key (no other credential uses it).
    func deletesKey(_ credential: StoredCredential) -> Bool {
        !credentials.contains { $0.id != credential.id && $0.keyTag == credential.keyTag }
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

    /// Takes an `openid-credential-offer://` or `openid4vp://` link opened from outside the app.
    func handle(url: URL) {
        if PresentationLink.isRequest(url.absoluteString) {
            incomingPresentation = IncomingOffer(text: url.absoluteString)
            return
        }
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

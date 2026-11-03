import Foundation

/// What the wallet shows before the user agrees to receive a credential (OpenID4VCI 1.0 Final,
/// pre-authorized code flow). Built only from verified issuer and authorization server metadata.
struct CredentialOfferPreview: Identifiable, Sendable {
    let id: UUID
    /// The Credential Issuer identifier (an https URL), exactly as the offer and metadata agree.
    let issuer: URL
    /// Display name the issuer gives itself, if any. Never presented as verified by Authrim.
    let issuerDisplayName: String?
    let credentialConfigurationId: String
    let credentialName: String
    /// Claim display names from the issuer metadata, in metadata order.
    let claimNames: [String]
    /// Present when the offer requires a transaction code (Authrim admin offers always do).
    let transactionCode: TransactionCodeRequirement?
}

struct TransactionCodeRequirement: Sendable, Equatable {
    let length: Int?
    let numeric: Bool
    let description: String?
}

/// A credential held by the wallet. The holder key lives in the Secure Enclave under `keyTag`;
/// the credential itself is stored as a device-only Keychain item, never synced or exported.
struct StoredCredential: Codable, Identifiable, Sendable, Equatable {
    let id: UUID
    let issuer: URL
    let issuerDisplayName: String?
    let credentialConfigurationId: String
    let vct: String
    let credentialName: String
    /// Disclosed claims as display strings (name → value), for the card and detail views.
    let claims: [String: String]
    let issuedAt: Date
    let expiresAt: Date?
    /// Secure Enclave key tag of this credential's own holder key.
    let keyTag: String
    /// `ABCD-EFGH`: first 8 base32 characters of the RFC 7638 thumbprint of the holder key, the
    /// same code the Authrim admin console shows after issuance.
    let confirmationCode: String
    /// The SD-JWT VC as issued (issuer JWT, disclosures, trailing `~`).
    let sdJwt: String
}

enum WalletError: Error, Equatable, Sendable {
    /// The scanned text is not an OpenID4VCI credential offer.
    case notAnOffer
    /// A URL that is not https, redirects, a size limit, a timeout or a non-success status.
    case network(String)
    /// Metadata or responses that contradict each other or the specification.
    case invalidIssuer(String)
    case transactionCodeRequired
    /// The issuer rejected the transaction code or the code expired (`invalid_grant`).
    case offerRejected
    /// The issued credential failed verification; nothing was stored.
    case invalidCredential(String)
    /// The user cancelled Face ID / passcode, or the Secure Enclave is unavailable.
    case keyUnavailable(String)
    case storage(String)
    /// The token step already spent the pre-authorized code and a later step failed (the text says which).
    /// The offer cannot be tried again; a new one is needed.
    case offerConsumed(String)
    /// The request may have reached the issuer, but its result never arrived (timeout, connection
    /// lost while waiting). Retryable for reads; after a token request it means the code may be spent.
    case outcomeUnknown(String)
}

/// Runs the issuance protocol. Implemented by `OpenID4VCIClient`; the UI only sees this.
protocol CredentialIssuanceService: Sendable {
    /// Resolve and validate an offer (scanned text or opened URL) into a preview.
    func preview(offer: String) async throws -> CredentialOfferPreview
    /// Create the holder key (asks for Face ID / passcode), run token → nonce → proof →
    /// credential, verify the credential, store it and return it.
    func issue(_ preview: CredentialOfferPreview, transactionCode: String?) async throws
        -> StoredCredential
}

/// Device-only storage of credentials. Deleting a credential also deletes its holder key.
protocol CredentialStore: Sendable {
    func loadAll() throws -> [StoredCredential]
    func save(_ credential: StoredCredential) throws
    func delete(_ credential: StoredCredential) throws
}

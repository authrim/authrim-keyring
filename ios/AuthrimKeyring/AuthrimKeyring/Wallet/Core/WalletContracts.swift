import Foundation

/// What the wallet shows before the user agrees to receive a credential.
struct OfferedCredential: Identifiable, Sendable {
    let id: String
    let name: String
    let claimNames: [String]
    let renewsCredential: Bool
}

struct CredentialOfferPreview: Identifiable, Sendable {
    let id: UUID
    /// The Credential Issuer identifier (an https URL), exactly as the offer and metadata agree.
    let issuer: URL
    /// The metadata-verified authorization server used for this offer's OAuth grant.
    let authorizationServer: URL
    /// Display name the issuer gives itself, if any. Never presented as verified by Authrim.
    let issuerDisplayName: String?
    let credential: OfferedCredential
    let additionalCredentials: [OfferedCredential]
    /// Supported offered configurations, in the order given by the issuer's offer.
    var credentials: [OfferedCredential] { [credential] + additionalCredentials }
    var credentialConfigurationId: String { credential.id }
    var credentialName: String { credential.name }
    var claimNames: [String] { credential.claimNames }
    /// Present when the offer requires a transaction code (Authrim admin offers always do).
    let transactionCode: TransactionCodeRequirement?
    /// The wallet must open the authorization server before requesting credentials.
    let authorizationRequired: Bool
    /// The new credential is bound to the key of a credential already on this device (the admin's
    /// registered second factor), instead of a new key.
    var renewsCredential: Bool { credential.renewsCredential }

    init(
        id: UUID, issuer: URL, authorizationServer: URL, issuerDisplayName: String?, credential: OfferedCredential,
        additionalCredentials: [OfferedCredential], transactionCode: TransactionCodeRequirement?,
        authorizationRequired: Bool = false
    ) {
        self.id = id
        self.issuer = issuer
        self.authorizationServer = authorizationServer
        self.issuerDisplayName = issuerDisplayName
        self.credential = credential
        self.additionalCredentials = additionalCredentials
        self.transactionCode = transactionCode
        self.authorizationRequired = authorizationRequired
    }

    /// Keeps callers that construct a one-credential preview source-compatible.
    init(
        id: UUID, issuer: URL, issuerDisplayName: String?, credentialConfigurationId: String,
        credentialName: String, claimNames: [String], transactionCode: TransactionCodeRequirement?,
        renewsCredential: Bool = false, authorizationServer: URL? = nil
    ) {
        self.init(
            id: id, issuer: issuer, authorizationServer: authorizationServer ?? issuer,
            issuerDisplayName: issuerDisplayName,
            credential: OfferedCredential(id: credentialConfigurationId, name: credentialName,
                                         claimNames: claimNames, renewsCredential: renewsCredential),
            additionalCredentials: [], transactionCode: transactionCode)
    }
}

struct TransactionCodeRequirement: Sendable, Equatable {
    let length: Int?
    let numeric: Bool
    let description: String?
}

/// A credential held by the wallet. The holder key lives in the Secure Enclave under `keyTag`;
/// the credential itself is stored as a device-only Keychain item, never synced or exported.
struct StoredCredential: Codable, Identifiable, Sendable, Hashable {
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
    /// Secure Enclave key tag of this credential's holder key. A renewed credential shares the key
    /// (and the tag) of the credential it renews.
    let keyTag: String
    /// `ABCD-EFGH`: first 8 base32 characters of the RFC 7638 thumbprint of the holder key, the
    /// same code the Authrim admin console shows after issuance.
    let confirmationCode: String
    /// The SD-JWT VC as issued (issuer JWT, disclosures, trailing `~`).
    let sdJwt: String
    /// When the user said the admin console shows the same confirmation code; nil until then.
    var confirmedAt: Date? = nil
    /// When the admin console accepted this credential's key as a second factor (a registration or
    /// a recovery request answered from this device); nil when not known to be one.
    var secondFactorRegisteredAt: Date? = nil
}

enum WalletError: Error, Equatable, Sendable {
    /// The scanned text is not an OpenID4VCI credential offer.
    case notAnOffer
    /// The offer contains no usable grant.
    case unsupportedGrant
    /// The person declined or cancelled authorization at the issuer.
    case authorizationDenied
    /// The issuer requires proof that the holder key meets a key-attestation policy.
    case unsupportedKeyAttestation
    /// The issuer requires credential request or response encryption this wallet cannot perform.
    case unsupportedCredentialEncryption
    /// A HAIP issuer's signing certificate cannot be checked against an independent trust source.
    case unsupportedIssuerCertificateTrust
    /// A URL that is not https, redirects, a size limit, a timeout or a non-success status.
    case network(String)
    /// Metadata or responses that contradict each other or the specification.
    case invalidIssuer(String)
    case transactionCodeRequired
    /// The issuer explicitly identified an incorrect transaction code; the same offer may be retried.
    case incorrectTransactionCode
    /// The code was rejected or expired, without evidence that correcting the transaction code can help.
    case offerRejected
    /// The issued credential failed verification; nothing was stored.
    case invalidCredential(String)
    /// The user cancelled Face ID / passcode, or the Secure Enclave is unavailable.
    case keyUnavailable(String)
    case storage(String)
    /// The token step already spent the one-time code and a later step failed (the text says which).
    /// The offer cannot be tried again; a new one is needed.
    case offerConsumed(String)
    /// The request may have reached the issuer, but its result never arrived (timeout, connection
    /// lost while waiting). Retryable for reads; after a token request it means the code may be spent.
    case outcomeUnknown(String)
    /// The scanned text is not an OpenID4VP request link.
    case notAPresentationRequest
    /// The request does not come from the issuer of a credential on this device; nothing was sent.
    case untrustedVerifier(String)
    /// The request is malformed, expired or asks for something the wallet does not give.
    case invalidRequest(String)
    /// No credential on this device answers the request.
    case noMatchingCredential
    /// The verifier refused the answer (e.g. a wrong number); a new request is needed.
    case presentationRefused(String?)
}

/// Runs the issuance protocol. Implemented by `OpenID4VCIClient`; the UI only sees this.
protocol CredentialIssuanceService: Sendable {
    /// Resolve and validate an offer (scanned text or opened URL) into a preview.
    func preview(offer: String) async throws -> CredentialOfferPreview
    /// Prepare and attest a holder key when required, run token → nonce → proof → credential,
    /// verify the credential, store it and return it.
    func issue(_ preview: CredentialOfferPreview, transactionCode: String?) async throws
        -> StoredCredential
    /// Uses the offer's one-time code once and requests each selected configuration in order.
    func issueAll(
        _ preview: CredentialOfferPreview, selectedConfigurationIds: [String], transactionCode: String?
    ) async throws -> [StoredCredential]
}

extension CredentialIssuanceService {
    /// One-credential implementations remain valid for previews they produce.
    func issueAll(
        _ preview: CredentialOfferPreview, selectedConfigurationIds: [String], transactionCode: String?
    ) async throws -> [StoredCredential] {
        guard selectedConfigurationIds == [preview.credentialConfigurationId] else {
            throw WalletError.invalidIssuer("This issuer cannot receive the selected credentials together.")
        }
        return [try await issue(preview, transactionCode: transactionCode)]
    }
}

/// Some credentials were verified and saved before a later credential request failed. The offer's
/// one-time grant has been used, so the user needs a fresh offer for the remaining credentials.
struct PartialIssuanceError: Error, Sendable {
    let saved: [StoredCredential]
    let failedCredentialName: String
    let reason: String
}

/// Device-only storage of credentials. Deleting a credential also deletes its holder key, unless
/// another stored credential still uses that key (a renewal).
protocol CredentialStore: Sendable {
    func loadAll() throws -> [StoredCredential]
    /// The credentials and how many stored items could not be read, so a caller can tell a
    /// complete list from one missing what it could not decode.
    func loadAllCountingSkipped() throws -> (items: [StoredCredential], skipped: Int)
    func save(_ credential: StoredCredential) throws
    func delete(_ credential: StoredCredential) throws
}

extension CredentialStore {
    func loadAllCountingSkipped() throws -> (items: [StoredCredential], skipped: Int) { (try loadAll(), 0) }
}

/// Answers administrator presentation requests (OpenID4VP 1.0, cross-device `direct_post`).
/// Implemented by `OpenID4VPClient`; the UI only sees this.
protocol PresentationService: Sendable {
    /// Fetch the request object, verify its signature and content, and pick the credential.
    func preview(link: String, credentials: [StoredCredential]) async throws -> PresentationRequest
    /// Sign the key binding with the credential's holder key (asks for Face ID / passcode),
    /// including the number typed by the user, and send the answer.
    func present(_ request: PresentationRequest, matchCode: String) async throws
}


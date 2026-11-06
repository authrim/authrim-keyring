import CryptoKit
import Foundation
import Testing
@testable import AuthrimKeyring

/// Renewing an admin credential with the holder key that is already the admin's second factor, and
/// what follows from keys shared between credentials. Serialized: the stub registry is shared.
extension StubbedNetworkTests {
@Suite(.serialized)
struct WalletRenewalTests {
    static let base = TestIssuer.base
    static let offerLink = "openid-credential-offer://?credential_offer_uri="
        + "https://issuer.example.com/vci/offers/ref1".addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
    let issuer = TestIssuer()
    let signer = TestSigner(tag: "com.authrim.keyring.vc.holder.old", key: P256.Signing.PrivateKey())
    let store = MemoryStore()
    let created = Box<[String]>([])
    let reused = Box<[String]>([])
    let deleted = Box<[String]>([])

    init() { StubURLProtocol.reset() }

    private var thumbprint: String { Base64URL.encode(signer.publicJWK.thumbprint) }

    private func client() -> OpenID4VCIClient {
        let signer = signer
        let (created, reused, deleted) = (created, reused, deleted)
        return OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            makeKey: { tag in
                created.value.append(tag)
                return TestSigner(tag: tag, key: P256.Signing.PrivateKey())
            },
            existingKey: { tag, jwk in
                reused.value.append(tag)
                #expect(jwk.isSameKey(as: signer.publicJWK))
                return TestSigner(tag: tag, key: signer.key)
            },
            deleteKey: { deleted.value.append($0) }, now: { Date() }, languages: { ["en"] })
    }

    /// The credential already on the device, bound to `signer`.
    private func existing(issuer url: String = TestIssuer.base, vct: String = TestIssuer.vct) throws -> StoredCredential {
        StoredCredential(
            id: UUID(), issuer: URL(string: url)!, issuerDisplayName: nil, credentialConfigurationId: "admin",
            vct: vct, credentialName: "Admin credential", claims: [:], issuedAt: Date().addingTimeInterval(-86_400),
            expiresAt: Date().addingTimeInterval(3600), keyTag: signer.tag,
            confirmationCode: signer.publicJWK.confirmationCode, sdJwt: try issuer.sdJwt(holder: signer.publicJWK),
            secondFactorRegisteredAt: Date().addingTimeInterval(-3600))
    }

    private func stubIssuance(credential: (() throws -> String)? = nil) {
        let b = Self.base
        StubURLProtocol.on("GET", b + "/vci/offers/ref1", json: TestIssuer.offerJSON())
        StubURLProtocol.on("GET", b + "/.well-known/openid-credential-issuer", json: TestIssuer.issuerMetadata())
        StubURLProtocol.on("GET", b + "/.well-known/oauth-authorization-server/vci", json: TestIssuer.serverMetadata())
        StubURLProtocol.on("POST", b + "/vci/token", json: ["access_token": "AT", "token_type": "Bearer", "expires_in": 300])
        StubURLProtocol.on("POST", b + "/vci/nonce", json: ["c_nonce": "NONCE-1"])
        StubURLProtocol.on("GET", b + "/.well-known/jwt-vc-issuer", json: issuer.jwks())
        let (signer, issuer) = (signer, issuer)
        StubURLProtocol.on("POST", b + "/vci/credential") { _ in
            let text = (try? credential?()) ?? ((try? issuer.sdJwt(holder: signer.publicJWK)) ?? "")
            let body = try! JSONSerialization.data(withJSONObject: ["credentials": [["credential": text]]])
            return .init(headers: ["Content-Type": "application/json"], body: body)
        }
    }

    // MARK: Hints

    @Test func readsTheRenewalHintsOfAnOfferLink() {
        let a = String(repeating: "A", count: 43), b = String(repeating: "b", count: 43)
        #expect(HolderKeyRenewal.hints(in: Self.offerLink + "&authrim_renew_holder_jkt=\(a),\(b)") == [a, b])
        #expect(HolderKeyRenewal.hints(in: Self.offerLink).isEmpty)
        // Malformed thumbprints are dropped; a repeated parameter or a long list is ignored.
        #expect(HolderKeyRenewal.hints(in: Self.offerLink + "&authrim_renew_holder_jkt=\(a),short,%2F%2F") == [a])
        #expect(HolderKeyRenewal.hints(
            in: Self.offerLink + "&authrim_renew_holder_jkt=\(a)&authrim_renew_holder_jkt=\(b)").isEmpty)
        let many = Array(repeating: a, count: HolderKeyRenewal.maxHints + 1).joined(separator: ",")
        #expect(HolderKeyRenewal.hints(in: Self.offerLink + "&authrim_renew_holder_jkt=\(many)").isEmpty)
    }

    // MARK: Issuance

    @Test func renewsWithTheKeyTheOfferNames() async throws {
        let old = try existing()
        store.items = [old]
        stubIssuance()
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink + "&authrim_renew_holder_jkt=\(thumbprint)")
        #expect(preview.renewsCredential)
        let renewed = try await client.issue(preview, transactionCode: "123456")

        #expect(renewed.keyTag == old.keyTag)
        #expect(renewed.confirmationCode == old.confirmationCode)
        // The same key is the same second factor.
        #expect(renewed.secondFactorRegisteredAt == old.secondFactorRegisteredAt)
        #expect(created.value.isEmpty && reused.value == [old.keyTag] && deleted.value.isEmpty)
        #expect(store.items.count == 2)
    }

    @Test(arguments: [
        ("another key", false, false),
        ("another issuer", true, false),
        ("another credential type", false, true),
    ])
    func createsANewKeyWhenNothingOnTheDeviceMatches(_ name: String, otherIssuer: Bool, otherType: Bool) async throws {
        store.items = [try existing(
            issuer: otherIssuer ? "https://other.example.com" : TestIssuer.base,
            vct: otherType ? "https://issuer.example.com/vct/other" : TestIssuer.vct)]
        stubIssuance()
        let hint = otherIssuer || otherType ? thumbprint : String(repeating: "Z", count: 43)
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink + "&authrim_renew_holder_jkt=\(hint)")
        #expect(!preview.renewsCredential)
        _ = try? await client.issue(preview, transactionCode: "123456")
        #expect(reused.value.isEmpty && created.value.count == 1)
    }

    @Test func refusesToRenewWhenTheStoredCredentialsCannotBeRead() async throws {
        stubIssuance()
        let failing = FailingLoadStore()
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: failing,
            makeKey: { _ in Issue.record("no new key"); return TestSigner(tag: "x", key: P256.Signing.PrivateKey()) },
            deleteKey: { _ in }, now: { Date() }, languages: { ["en"] })
        // Issuing with a new key instead would silently lose the second factor.
        await #expect(throws: WalletError.self) {
            _ = try await client.preview(offer: Self.offerLink + "&authrim_renew_holder_jkt=\(thumbprint)")
        }
        // Without a hint, the stored credentials are not needed.
        _ = try await client.preview(offer: Self.offerLink)
    }

    @Test func refusesToRenewWhenTheCredentialToRenewMightBeUnreadable() async throws {
        stubIssuance()
        let store = SkippingStore()
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            makeKey: { _ in Issue.record("no new key"); return TestSigner(tag: "x", key: P256.Signing.PrivateKey()) },
            deleteKey: { _ in }, now: { Date() }, languages: { ["en"] })
        await #expect(throws: WalletError.self) {
            _ = try await client.preview(offer: Self.offerLink + "&authrim_renew_holder_jkt=\(thumbprint)")
        }
    }

    @Test func reservesTheReusedKeyBeforeTheOfferIsSpent() async throws {
        let old = try existing()
        store.items = [old]
        stubIssuance()
        let tag = old.keyTag
        let reservedAtToken = Box<Bool?>(nil)
        // The token request spends the offer: the key must already be reserved then.
        StubURLProtocol.on("POST", Self.base + "/vci/token") { _ in
            reservedAtToken.value = HolderKeyReservations.shared.isReserved(tag)
            let body = try! JSONSerialization.data(withJSONObject: ["access_token": "AT", "token_type": "Bearer", "expires_in": 300])
            return .init(headers: ["Content-Type": "application/json"], body: body)
        }
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink + "&authrim_renew_holder_jkt=\(thumbprint)")
        _ = try await client.issue(preview, transactionCode: "123456")
        #expect(reservedAtToken.value == true)
        #expect(!HolderKeyReservations.shared.isReserved(tag))
    }

    @Test func stopsBeforeSpendingTheOfferWhenTheRenewedCredentialWasRemoved() async throws {
        store.items = [try existing()]
        stubIssuance()
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink + "&authrim_renew_holder_jkt=\(thumbprint)")
        store.items = []
        await #expect(throws: WalletError.self) { try await client.issue(preview, transactionCode: "123456") }
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").isEmpty)
    }

    @Test func takesTheRegistrationRecordedAfterThePreview() async throws {
        var old = try existing()
        old.secondFactorRegisteredAt = nil
        store.items = [old]
        stubIssuance()
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink + "&authrim_renew_holder_jkt=\(thumbprint)")
        // The key is registered (an enrolment from this device) while the offer is open.
        let at = Date()
        store.items[0].secondFactorRegisteredAt = at
        let renewed = try await client.issue(preview, transactionCode: "123456")
        #expect(renewed.secondFactorRegisteredAt == at)
    }

    @Test func keepsTheRegistrationWhenTheRenewedCredentialIsDeletedDuringIssuance() async throws {
        let old = try existing()
        store.items = [old]
        stubIssuance()
        let store = store
        // The renewed credential is deleted after the offer is spent.
        StubURLProtocol.on("POST", Self.base + "/vci/nonce") { _ in
            store.items = []
            let body = try! JSONSerialization.data(withJSONObject: ["c_nonce": "NONCE-1"])
            return .init(headers: ["Content-Type": "application/json"], body: body)
        }
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink + "&authrim_renew_holder_jkt=\(thumbprint)")
        let renewed = try await client.issue(preview, transactionCode: "123456")
        #expect(renewed.secondFactorRegisteredAt == old.secondFactorRegisteredAt)
    }

    @Test(arguments: [
        ("someone-else", true),
        // Canonically equivalent to "user-1é" but another identifier.
        ("user-1e\u{0301}", false),
        (nil, true),
    ] as [(String?, Bool)])
    func refusesARenewalThatNamesAnotherAdministrator(_ subject: String?, plainOld: Bool) async throws {
        var old = try existing()
        if !plainOld {
            var options = TestIssuer.Options()
            options.extraPayload = ["sub": "user-1\u{00E9}"]
            old = StoredCredential(
                id: old.id, issuer: old.issuer, issuerDisplayName: nil, credentialConfigurationId: old.credentialConfigurationId,
                vct: old.vct, credentialName: old.credentialName, claims: [:], issuedAt: old.issuedAt,
                expiresAt: old.expiresAt, keyTag: old.keyTag, confirmationCode: old.confirmationCode,
                sdJwt: try issuer.sdJwt(holder: signer.publicJWK, options), secondFactorRegisteredAt: old.secondFactorRegisteredAt)
        }
        store.items = [old]
        // Someone else's offer naming this device's key.
        let (issuer, signer) = (issuer, signer)
        stubIssuance(credential: {
            var options = TestIssuer.Options()
            options.extraPayload = ["sub": subject.map { $0 as Any } ?? NSNull()]
            return try issuer.sdJwt(holder: signer.publicJWK, options)
        })
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink + "&authrim_renew_holder_jkt=\(thumbprint)")
        await #expect(throws: WalletError.self) { try await client.issue(preview, transactionCode: "123456") }
        #expect(store.items.count == 1)
        #expect(deleted.value.isEmpty)
    }

    @Test func neverDeletesTheReusedKeyWhenRenewalFails() async throws {
        store.items = [try existing()]
        stubIssuance(credential: { "not-a-credential" })
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink + "&authrim_renew_holder_jkt=\(thumbprint)")
        await #expect(throws: WalletError.self) { try await client.issue(preview, transactionCode: "123456") }
        // The earlier credential still needs the key.
        #expect(deleted.value.isEmpty)
        #expect(store.items.count == 1)
    }
}
}

/// A store whose list cannot be read.
final class FailingLoadStore: CredentialStore, @unchecked Sendable {
    func loadAll() throws -> [StoredCredential] { throw WalletError.storage("locked") }
    func save(_ credential: StoredCredential) throws {}
    func delete(_ credential: StoredCredential) throws {}
}

/// A store with one item it could not read.
final class SkippingStore: CredentialStore, @unchecked Sendable {
    func loadAll() throws -> [StoredCredential] { [] }
    func loadAllCountingSkipped() throws -> (items: [StoredCredential], skipped: Int) { ([], 1) }
    func save(_ credential: StoredCredential) throws {}
    func delete(_ credential: StoredCredential) throws {}
}

/// An item of the credential service that does not decode as a credential.
private struct UnreadableItem: Codable, Identifiable {
    let id: UUID
    let unrelated: Int
}

/// Choosing the credential that answers a request, and keys shared between stored credentials.
@Suite(.serialized)
struct WalletSharedKeyTests {
    private func credential(
        tag: String, issuedHoursAgo: Double, registered: Bool = false
    ) -> StoredCredential {
        StoredCredential(
            id: UUID(), issuer: URL(string: "https://issuer.example.com")!, issuerDisplayName: nil,
            credentialConfigurationId: "admin", vct: "v", credentialName: "Admin", claims: [:],
            issuedAt: Date().addingTimeInterval(-issuedHoursAgo * 3600), expiresAt: nil, keyTag: tag,
            confirmationCode: "ABCD-EFGH", sdJwt: "a.b.c~",
            secondFactorRegisteredAt: registered ? Date() : nil)
    }

    @Test func aStepUpOffersTheRegisteredKeyFirstAndOneCredentialPerKey() {
        let registeredOld = credential(tag: "k1", issuedHoursAgo: 48, registered: true)
        let registeredNew = credential(tag: "k1", issuedHoursAgo: 2, registered: true)
        let unregistered = credential(tag: "k2", issuedHoursAgo: 1)

        let stepUp = PresentationRequestValidator.preferred([registeredOld, unregistered, registeredNew], for: .stepUp)
        #expect(stepUp.map(\.id) == [registeredNew.id, unregistered.id])

        // A registration presents the newest key.
        let enroll = PresentationRequestValidator.preferred([registeredOld, unregistered, registeredNew], for: .enroll)
        #expect(enroll.map(\.id) == [unregistered.id, registeredNew.id])
    }

    @Test func answeringWithAnotherCandidateOnly() {
        let a = credential(tag: "k1", issuedHoursAgo: 1)
        let b = credential(tag: "k2", issuedHoursAgo: 2)
        let stranger = credential(tag: "k3", issuedHoursAgo: 3)
        var request = PresentationRequest(
            clientID: "c", verifierHost: "issuer.example.com", responseURI: URL(string: "https://issuer.example.com/r")!,
            nonce: "n", state: "s", expiresAt: Date().addingTimeInterval(60), transactionData: "t", purpose: .stepUp,
            tenant: "", credential: a)
        request.candidates = [a, b]
        #expect(request.answering(with: b).credential.id == b.id)
        #expect(request.answering(with: stranger).credential.id == a.id)
    }

    @Test func deletingACredentialKeepsAKeyAnotherOneStillUses() throws {
        let deletedTags = Box<[String]>([])
        let store = KeychainCredentialStore(service: "com.authrim.keyring.vc.test.\(UUID().uuidString)") {
            deletedTags.value.append($0)
        }
        let old = credential(tag: "shared", issuedHoursAgo: 48)
        let renewed = credential(tag: "shared", issuedHoursAgo: 1)
        try store.save(old)
        try store.save(renewed)

        try store.delete(old)
        #expect(deletedTags.value.isEmpty)
        try store.delete(renewed)
        #expect(deletedTags.value == ["shared"])
        #expect(try store.loadAll().isEmpty)
    }

    @Test func keepsTheKeyWhileARenewalSignsWithIt() throws {
        let deletedTags = Box<[String]>([])
        let store = KeychainCredentialStore(service: "com.authrim.keyring.vc.test.\(UUID().uuidString)") {
            deletedTags.value.append($0)
        }
        let old = credential(tag: "renewing-\(UUID().uuidString)", issuedHoursAgo: 48)
        try store.save(old)
        HolderKeyReservations.shared.reserve(old.keyTag)
        try store.delete(old)
        HolderKeyReservations.shared.release(old.keyTag)
        #expect(deletedTags.value.isEmpty)
        #expect(!HolderKeyReservations.shared.isReserved(old.keyTag))
    }

    @Test func keepsTheKeyWhenAnItemCouldNotBeRead() throws {
        let service = "com.authrim.keyring.vc.test.\(UUID().uuidString)"
        let deletedTags = Box<[String]>([])
        let store = KeychainCredentialStore(service: service) { deletedTags.value.append($0) }
        let item = credential(tag: "maybe-shared", issuedHoursAgo: 1)
        try store.save(item)
        // Perhaps the unreadable item is the renewed credential using the same key.
        let unreadable = UnreadableItem(id: UUID(), unrelated: 1)
        try KeychainStore(service: service).save(unreadable, to: .device)
        try store.delete(item)
        #expect(deletedTags.value.isEmpty)
        try KeychainStore(service: service).delete(id: unreadable.id, from: .device)
    }
}

/// Recording the registration after an answered request: an ordinary registration marks the key,
/// a recovery request does not (its key is a factor only once the recovery completes).
@MainActor
@Suite(.serialized)
struct WalletRegistrationMarkTests {
    private struct AnsweringService: PresentationService {
        let request: PresentationRequest
        func preview(link: String, credentials: [StoredCredential]) async throws -> PresentationRequest { request }
        func present(_ request: PresentationRequest, matchCode: String) async throws {}
    }

    private struct NoIssuance: CredentialIssuanceService {
        func preview(offer: String) async throws -> CredentialOfferPreview { throw WalletError.notAnOffer }
        func issue(_ preview: CredentialOfferPreview, transactionCode: String?) async throws -> StoredCredential {
            throw WalletError.notAnOffer
        }
    }

    @Test(arguments: [false, true])
    func marksOnlyAnOrdinaryRegistration(isRecovery: Bool) async throws {
        let credential = StoredCredential(
            id: UUID(), issuer: URL(string: "https://issuer.example.com")!, issuerDisplayName: nil,
            credentialConfigurationId: "admin", vct: "v", credentialName: "Admin", claims: [:], issuedAt: Date(),
            expiresAt: nil, keyTag: "k", confirmationCode: "ABCD-EFGH", sdJwt: "a.b.c~")
        var request = PresentationRequest(
            clientID: "c", verifierHost: "issuer.example.com", responseURI: URL(string: "https://issuer.example.com/r")!,
            nonce: "n", state: "s", expiresAt: Date().addingTimeInterval(60), transactionData: "t", purpose: .enroll,
            tenant: "", credential: credential)
        request.isRecovery = isRecovery
        request.candidates = [credential]
        let store = MemoryStore()
        store.items = [credential]
        let wallet = WalletModel(issuance: NoIssuance(), store: store, presentation: AnsweringService(request: request))
        wallet.load()
        let flow = PresentationFlow(link: "openid4vp://x")
        await flow.start(using: wallet)
        flow.matchCode = "42"
        await flow.approve(request, using: wallet)
        #expect(flow.isDone)
        #expect((wallet.credentials.first?.secondFactorRegisteredAt != nil) == !isRecovery)
    }
}

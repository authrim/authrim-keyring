import CryptoKit
import Foundation
import Testing
@testable import AuthrimKeyring

/// Offer parsing, metadata validation and the issue flow, with the network stubbed.
/// Serialized: the stub registry is shared.
extension StubbedNetworkTests {
@Suite(.serialized)
struct WalletIssuanceTests {
    static let base = TestIssuer.base
    static let offerLink = "openid-credential-offer://?credential_offer_uri=" + "https://issuer.example.com/vci/offers/ref1".addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
    let issuer = TestIssuer()
    let signer = TestSigner(tag: "com.authrim.keyring.vc.holder.test", key: P256.Signing.PrivateKey())
    let store = MemoryStore()
    let deleted = Box<[String]>([])

    init() { StubURLProtocol.reset() }

    private func client(languages: [String] = ["en"]) -> OpenID4VCIClient {
        let signer = signer
        let deleted = deleted
        return OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            makeKey: { _ in signer }, deleteKey: { deleted.value.append($0) },
            now: { Date() }, languages: { languages })
    }

    private func stubHappyPath(
        offer: [String: Any]? = nil, metadata: [String: Any]? = nil, server: [String: Any]? = nil,
        credential: (() throws -> String)? = nil
    ) {
        let b = Self.base
        StubURLProtocol.on("GET", b + "/vci/offers/ref1", json: offer ?? TestIssuer.offerJSON())
        StubURLProtocol.on("GET", b + "/.well-known/openid-credential-issuer", json: metadata ?? TestIssuer.issuerMetadata())
        StubURLProtocol.on("GET", b + "/.well-known/oauth-authorization-server/vci", json: server ?? TestIssuer.serverMetadata())
        StubURLProtocol.on("POST", b + "/vci/token", json: ["access_token": "AT", "token_type": "Bearer", "expires_in": 300])
        StubURLProtocol.on("POST", b + "/vci/nonce", json: ["c_nonce": "NONCE-1"])
        StubURLProtocol.on("GET", b + "/.well-known/jwt-vc-issuer", json: issuer.jwks())
        let signer = signer
        let issuer = issuer
        StubURLProtocol.on("POST", b + "/vci/credential") { _ in
            let text = (try? credential?()) ?? ((try? issuer.sdJwt(holder: signer.publicJWK)) ?? "")
            let body = try! JSONSerialization.data(withJSONObject: ["credentials": [["credential": text]]])
            return .init(headers: ["Content-Type": "application/json"], body: body)
        }
    }

    // MARK: Offer parsing

    @Test func offerSources() throws {
        #expect(try CredentialOfferParser.source(of: Self.offerLink) == .reference(URL(string: Self.base + "/vci/offers/ref1")!))
        let json = #"{"a":1}"#.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        #expect(try CredentialOfferParser.source(of: "openid-credential-offer://?credential_offer=\(json)") == .inline(Data(#"{"a":1}"#.utf8)))
    }

    @Test(arguments: [
        "https://example.com/not-an-offer",
        "openid-credential-offer://?foo=bar",
        "openid-credential-offer://?credential_offer_uri=http%3A%2F%2Fissuer.example.com%2Foffer",
        "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fa.example%2Fo&credential_offer=%7B%7D",
        "haip-vci://?credential_offer_uri=https%3A%2F%2Fa.example%2Fo",
        "openid-credential-offer://?credential_offer_uri=https%3A%2F%2F192.168.1.10%2Fo",
        "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Frouter.local%2Fo",
        "",
    ])
    func invalidOffers(text: String) {
        #expect(throws: WalletError.notAnOffer) { try CredentialOfferParser.source(of: text) }
    }

    @Test func offerJSONRequiresPreAuthorizedGrant() throws {
        let parsed = try CredentialOfferParser.parse(json: JSONSerialization.data(withJSONObject: TestIssuer.offerJSON()))
        #expect(parsed.preAuthorizedCode == "PRE-CODE")
        #expect(parsed.transactionCode == .init(inputMode: "numeric", length: 6, description: "Shown in the console"))
        let noGrant: [String: Any] = ["credential_issuer": Self.base, "credential_configuration_ids": ["admin"], "grants": [:]]
        #expect(throws: WalletError.self) { try CredentialOfferParser.parse(json: JSONSerialization.data(withJSONObject: noGrant)) }
        #expect(throws: WalletError.notAnOffer) { try CredentialOfferParser.parse(json: Data("nope".utf8)) }
    }

    // MARK: Preview

    @Test func previewFromOfferURI() async throws {
        stubHappyPath()
        let preview = try await client().preview(offer: Self.offerLink)
        #expect(preview.issuer.absoluteString == Self.base)
        #expect(preview.issuerDisplayName == "Autorim")
        #expect(preview.credentialName == "Admin credential")
        #expect(preview.claimNames == ["Email", "Name"])
        #expect(preview.transactionCode == TransactionCodeRequirement(length: 6, numeric: true, description: "Shown in the console"))
    }

    @Test func previewLocalizedAndInline() async throws {
        stubHappyPath()
        let json = try String(data: JSONSerialization.data(withJSONObject: TestIssuer.offerJSON(txCode: false)), encoding: .utf8)!
        let link = "openid-credential-offer://?credential_offer=" + json.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        let preview = try await client(languages: ["ja-JP", "en-US"]).preview(offer: link)
        #expect(preview.credentialName == "管理者資格")
        #expect(preview.claimNames == ["メール", "Name"])
        #expect(preview.transactionCode == nil)
    }

    @Test(arguments: [
        "localhost", "printer.local", "db.internal", "127.0.0.1", "127.1", "2130706433", "10.0.0.8",
        "172.20.1.1", "192.168.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "[::1]", "[fe80::1]",
        "[fd00::1]", "[::ffff:192.168.0.1]", "[::127.0.0.1]", "[::]", "[64:ff9b::a00:1]", "[ff02::1]",
        "239.0.0.1", "255.255.255.255", "192.0.0.8", "192.0.0.255", "198.18.0.1",
    ])
    func rejectsNonPublicHosts(host: String) {
        #expect(throws: WalletError.self) { try WalletHTTP.requireHTTPS(URL(string: "https://\(host)/x")!, "The URL") }
    }

    @Test func acceptsPublicHosts() throws {
        for host in ["issuer.example.com", "8.8.8.8", "[2001:db8::1]", "172.32.0.1", "192.0.1.1", "[::ffff:192.0.1.1]"] {
            _ = try WalletHTTP.requireHTTPS(URL(string: "https://\(host)/x")!, "The URL")
        }
    }

    @Test(arguments: [
        "https://host.example/a/../b", "https://host.example/a/./b", "https://host.example/a//b",
        "https://host.example/a/%2e%2e/b", "https://host.example/a/", "https://host.example/a%2Fb",
    ])
    func rejectsNonNormalizedIssuerPaths(identifier: String) {
        #expect(throws: WalletError.self) { try IssuerMetadata.issuerURL(identifier) }
    }

    @Test func pathInsertedWellKnown() {
        let url = URL(string: "https://host.example/tenant/a")!
        #expect(IssuerMetadata.wellKnownURL(for: url, suffix: "openid-credential-issuer")?.absoluteString == "https://host.example/.well-known/openid-credential-issuer/tenant/a")
        #expect(IssuerMetadata.wellKnownURL(for: URL(string: "https://host.example")!, suffix: "jwt-vc-issuer")?.absoluteString == "https://host.example/.well-known/jwt-vc-issuer")
        #expect(IssuerMetadata.wellKnownURL(for: URL(string: "https://host.example/a%3Ab")!, suffix: "openid-credential-issuer")?.absoluteString == "https://host.example/.well-known/openid-credential-issuer/a%3Ab")
        let longVct = "https://issuer.example.com/vct/" + String(repeating: "a", count: 200)
        #expect(IssuerMetadata.sanitize(longVct, maxLength: 512) == longVct)
    }

    @Test func rejectsIssuerMismatch() async {
        stubHappyPath(metadata: TestIssuer.issuerMetadata(issuer: Self.base + "/"))
        await #expect(throws: WalletError.self) { try await client().preview(offer: Self.offerLink) }
    }

    @Test func rejectsServerIssuerMismatch() async {
        stubHappyPath(server: TestIssuer.serverMetadata(issuer: "https://evil.example.com/vci"))
        await #expect(throws: WalletError.self) { try await client().preview(offer: Self.offerLink) }
    }

    @Test func rejectsMultipleAuthorizationServers() async {
        stubHappyPath(metadata: TestIssuer.issuerMetadata(servers: [Self.base + "/vci", Self.base + "/other"]))
        await #expect(throws: WalletError.self) { try await client().preview(offer: Self.offerLink) }
    }

    @Test func rejectsEndpointsOnAnotherOrigin() async {
        stubHappyPath(metadata: TestIssuer.issuerMetadata(credentialEndpoint: "https://evil.example.com/credential"))
        await #expect(throws: WalletError.self) { try await client().preview(offer: Self.offerLink) }
        stubHappyPath(metadata: TestIssuer.issuerMetadata(nonceEndpoint: "https://evil.example.com/nonce"))
        await #expect(throws: WalletError.self) { try await client().preview(offer: Self.offerLink) }
        stubHappyPath(server: TestIssuer.serverMetadata(tokenEndpoint: "https://evil.example.com/token"))
        await #expect(throws: WalletError.self) { try await client().preview(offer: Self.offerLink) }
    }

    @Test func rejectsHTTPEndpoint() async {
        stubHappyPath(metadata: TestIssuer.issuerMetadata(credentialEndpoint: "http://issuer.example.com/vci/credential"))
        await #expect(throws: WalletError.self) { try await client().preview(offer: Self.offerLink) }
    }

    @Test func rejectsUnsupportedFormat() async {
        stubHappyPath(metadata: TestIssuer.issuerMetadata(format: "jwt_vc_json"))
        await #expect(throws: WalletError.self) { try await client().preview(offer: Self.offerLink) }
    }

    @Test func doesNotFollowRedirects() async {
        stubHappyPath()
        StubURLProtocol.on("GET", Self.base + "/.well-known/openid-credential-issuer") { _ in
            .init(redirectTo: URL(string: "https://evil.example.com/metadata")!)
        }
        StubURLProtocol.on("GET", "https://evil.example.com/metadata", json: TestIssuer.issuerMetadata())
        await #expect(throws: WalletError.self) { try await client().preview(offer: Self.offerLink) }
        #expect(StubURLProtocol.requests(to: "https://evil.example.com/metadata").isEmpty)
    }

    @Test func capsResponseSize() async {
        stubHappyPath()
        StubURLProtocol.on("GET", Self.base + "/vci/offers/ref1") { _ in .init(body: Data(repeating: 0x20, count: 70_000)) }
        await #expect(throws: WalletError.self) { try await client().preview(offer: Self.offerLink) }
    }

    // MARK: Issue

    @Test func issuesAndStores() async throws {
        stubHappyPath()
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink)
        let stored = try await client.issue(preview, transactionCode: " 123456 ")

        let tokenBody = String(decoding: try #require(StubURLProtocol.body(of: Self.base + "/vci/token")), as: UTF8.self)
        #expect(tokenBody.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code"))
        #expect(tokenBody.contains("pre-authorized_code=PRE-CODE") && tokenBody.contains("tx_code=123456"))

        let request = try #require(StubURLProtocol.requests(to: Self.base + "/vci/credential").first)
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer AT")
        let rawBody = try #require(StubURLProtocol.body(of: Self.base + "/vci/credential"))
        let body = try #require(JSONSerialization.jsonObject(with: rawBody) as? [String: Any])
        #expect(body["credential_configuration_id"] as? String == "admin")
        let proof = try #require(((body["proofs"] as? [String: Any])?["jwt"] as? [String])?.first)
        let parts = try #require(JWS.parse(proof))
        #expect(parts.payload["nonce"] as? String == "NONCE-1")
        #expect(parts.payload["aud"] as? String == Self.base)
        #expect(JWS.verifyES256(parts, with: signer.key.publicKey))

        #expect(store.items == [stored])
        #expect(stored.keyTag == signer.tag || stored.keyTag.hasPrefix(HolderKey.tagPrefix))
        #expect(stored.confirmationCode == signer.publicJWK.confirmationCode)
        #expect(stored.claims["email"] == "admin@example.com")
        #expect(stored.vct == TestIssuer.vct && deleted.value.isEmpty)
    }

    @Test func requiresTransactionCode() async throws {
        stubHappyPath()
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink)
        await #expect(throws: WalletError.transactionCodeRequired) { try await client.issue(preview, transactionCode: nil) }
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").isEmpty)
    }

    @Test func wrongTransactionCodeIsRejected() async throws {
        stubHappyPath()
        StubURLProtocol.on("POST", Self.base + "/vci/token", json: ["error": "invalid_grant"], status: 400)
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink)
        await #expect(throws: WalletError.offerRejected) { try await client.issue(preview, transactionCode: "000000") }
        #expect(store.items.isEmpty && deleted.value.isEmpty)
    }

    @Test func invalidCredentialDeletesKeyAndStoresNothing() async throws {
        var options = TestIssuer.Options()
        options.iss = "https://evil.example.com"
        let signer = signer
        let issuer = issuer
        stubHappyPath(credential: { try issuer.sdJwt(holder: signer.publicJWK, options) })
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink)
        await #expect(throws: WalletError.self) { try await client.issue(preview, transactionCode: "123456") }
        #expect(store.items.isEmpty)
        #expect(deleted.value.count == 1)
    }

    @Test func credentialRejectionDeletesKey() async throws {
        stubHappyPath()
        StubURLProtocol.on("POST", Self.base + "/vci/credential", json: ["error": "invalid_proof"], status: 400)
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink)
        await #expect(throws: WalletError.self) { try await client.issue(preview, transactionCode: "123456") }
        #expect(store.items.isEmpty && deleted.value.count == 1)
    }

    @Test func storageFailureDeletesKey() async throws {
        stubHappyPath()
        store.failSave = true
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink)
        await #expect(throws: WalletError.offerConsumed("full")) { try await client.issue(preview, transactionCode: "123456") }
        #expect(deleted.value.count == 1)
    }

    @Test func failureAfterTokenIsTerminalAndNeverReusesTheCode() async throws {
        stubHappyPath()
        StubURLProtocol.on("POST", Self.base + "/vci/nonce", json: ["error": "server_error"], status: 500)
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink)
        await #expect(throws: WalletError.self) { try await client.issue(preview, transactionCode: "123456") }
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").count == 1)

        // A second attempt with the same preview must not exchange the code again.
        await #expect(throws: WalletError.invalidIssuer("This offer is no longer available. Scan it again.")) {
            try await client.issue(preview, transactionCode: "123456")
        }
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").count == 1)
        #expect(!WalletError.offerConsumed("x").canRetry)
    }

    @Test func keyCancellationAfterTokenIsTerminal() async throws {
        stubHappyPath()
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            makeKey: { _ in throw WalletError.keyUnavailable("Cancelled.") }, deleteKey: { _ in },
            now: { Date() }, languages: { ["en"] })
        let preview = try await client.preview(offer: Self.offerLink)
        await #expect(throws: WalletError.offerConsumed("Cancelled.")) { try await client.issue(preview, transactionCode: "123456") }
    }

    @Test func tokenStepNetworkFailureStaysRetryable() async throws {
        stubHappyPath()
        StubURLProtocol.on("POST", Self.base + "/vci/token", json: ["error": "server_error"], status: 500)
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink)
        await #expect(throws: WalletError.network("The token request failed (HTTP 500).")) {
            try await client.issue(preview, transactionCode: "123456")
        }
        StubURLProtocol.on("POST", Self.base + "/vci/token", json: ["access_token": "AT", "token_type": "Bearer", "expires_in": 300])
        _ = try await client.issue(preview, transactionCode: "123456")
        #expect(store.items.count == 1)
    }

    @Test func tokenTimeoutIsTerminalAndNeverReusesTheCode() async throws {
        stubHappyPath()
        StubURLProtocol.on("POST", Self.base + "/vci/token") { _ in .init(failWith: .timedOut) }
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink)
        await #expect(throws: WalletError.self) { try await client.issue(preview, transactionCode: "123456") }
        do {
            _ = try await client.issue(preview, transactionCode: "123456")
            Issue.record("A second attempt must not run")
        } catch let error as WalletError {
            #expect(!error.canRetry || error == .invalidIssuer("This offer is no longer available. Scan it again."))
        }
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").count == 1)
    }

    @Test func tokenTimeoutReportsTheOfferAsConsumed() async throws {
        stubHappyPath()
        StubURLProtocol.on("POST", Self.base + "/vci/token") { _ in .init(failWith: .networkConnectionLost) }
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink)
        do {
            _ = try await client.issue(preview, transactionCode: "123456")
            Issue.record("Expected a failure")
        } catch let error as WalletError {
            guard case .offerConsumed = error else {
                Issue.record("Expected offerConsumed, got \(error)")
                return
            }
            #expect(!error.canRetry)
        }
    }

    @Test func tokenConnectionRefusedBeforeSendingStaysRetryable() async throws {
        stubHappyPath()
        StubURLProtocol.on("POST", Self.base + "/vci/token") { _ in .init(failWith: .cannotConnectToHost) }
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink)
        do {
            _ = try await client.issue(preview, transactionCode: "123456")
            Issue.record("Expected a failure")
        } catch let error as WalletError {
            guard case .network = error else {
                Issue.record("Expected network, got \(error)")
                return
            }
            #expect(error.canRetry)
        }
        StubURLProtocol.on("POST", Self.base + "/vci/token", json: ["access_token": "AT", "token_type": "Bearer", "expires_in": 300])
        _ = try await client.issue(preview, transactionCode: "123456")
        #expect(store.items.count == 1)
    }

    @Test func unreadableTokenSuccessIsTerminal() async throws {
        stubHappyPath()
        StubURLProtocol.on("POST", Self.base + "/vci/token", json: ["unexpected": true])
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink)
        await #expect(throws: WalletError.offerConsumed("The token response is not a bearer token.")) {
            try await client.issue(preview, transactionCode: "123456")
        }
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").count == 1)
    }

    @Test func oversizedTokenSuccessIsTerminal() async throws {
        stubHappyPath()
        StubURLProtocol.on("POST", Self.base + "/vci/token") { _ in .init(body: Data(repeating: 0x20, count: 70_000)) }
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink)
        await #expect(throws: WalletError.offerConsumed("The response is too large.")) {
            try await client.issue(preview, transactionCode: "123456")
        }
        // A retry with the same preview never exchanges the code again.
        await #expect(throws: WalletError.self) { try await client.issue(preview, transactionCode: "123456") }
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").count == 1)
    }
}
}

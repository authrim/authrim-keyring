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

    private static let learningVct = base + "/vct/learning"

    private func multiConfigurationMetadata() -> [String: Any] {
        var metadata = TestIssuer.issuerMetadata()
        var configurations = metadata["credential_configurations_supported"] as! [String: Any]
        var learning = configurations["admin"] as! [String: Any]
        learning["vct"] = Self.learningVct
        learning["scope"] = "learning"
        var credentialMetadata = learning["credential_metadata"] as! [String: Any]
        credentialMetadata["display"] = [["name": "Learning credential", "locale": "en"]]
        learning["credential_metadata"] = credentialMetadata
        configurations["learning"] = learning
        metadata["credential_configurations_supported"] = configurations
        return metadata
    }

    private func multiClient(
        signers: Box<[TestSigner]>, requests: Box<[[String: Any]]>, rejectSecond: Bool = false,
        delegatedEndpoints: Bool = false
    ) -> OpenID4VCIClient {
        var metadata = multiConfigurationMetadata()
        if delegatedEndpoints {
            metadata["authorization_servers"] = ["https://auth.example.com"]
            metadata["credential_endpoint"] = "https://backend.example.com/credential"
            metadata["nonce_endpoint"] = "https://backend.example.com/nonce"
        }
        stubHappyPath(
            offer: TestIssuer.offerJSON(ids: ["admin", "learning"]),
            metadata: metadata)
        if delegatedEndpoints {
            StubURLProtocol.on(
                "GET", "https://auth.example.com/.well-known/oauth-authorization-server",
                json: TestIssuer.serverMetadata(
                    issuer: "https://auth.example.com", tokenEndpoint: "https://auth.example.com/token"))
            StubURLProtocol.on(
                "POST", "https://auth.example.com/token",
                json: ["access_token": "AT", "token_type": "Bearer", "expires_in": 300])
            StubURLProtocol.on("POST", "https://backend.example.com/nonce", json: ["c_nonce": "NONCE-2"])
        }
        let endpoint = delegatedEndpoints ? "https://backend.example.com/credential" : Self.base + "/vci/credential"
        let issuer = issuer
        StubURLProtocol.on("POST", endpoint) { _ in
            guard let data = StubURLProtocol.body(of: endpoint),
                  let body = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
            else { return .init(status: 400) }
            requests.value.append(body)
            if rejectSecond && requests.value.count == 2 {
                return .init(status: 400, body: Data(#"{"error":"invalid_proof"}"#.utf8))
            }
            guard let signer = signers.value.last else { return .init(status: 400) }
            var options = TestIssuer.Options()
            options.vct = requests.value.count == 1 ? TestIssuer.vct : Self.learningVct
            let credential = try! issuer.sdJwt(holder: signer.publicJWK, options)
            return .init(
                headers: ["Content-Type": "application/json"],
                body: try! JSONSerialization.data(withJSONObject: ["credentials": [["credential": credential]]]))
        }
        let deleted = deleted
        return OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            makeKey: { tag in
                let signer = TestSigner(tag: tag, key: P256.Signing.PrivateKey())
                signers.value.append(signer)
                return signer
            },
            deleteKey: { deleted.value.append($0) },
            now: { Date() }, languages: { ["en"] })
    }

    // MARK: Offer parsing

    @Test func offerSources() throws {
        #expect(try CredentialOfferParser.source(of: Self.offerLink) == .reference(URL(string: Self.base + "/vci/offers/ref1")!))
        let json = #"{"a":1}"#.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        #expect(try CredentialOfferParser.source(of: "openid-credential-offer://?credential_offer=\(json)") == .inline(Data(#"{"a":1}"#.utf8)))
        let reference = (Self.base + "/vci/offers/ref1").addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        #expect(try CredentialOfferParser.source(of: "haip-vci://credential_offer?credential_offer_uri=\(reference)") == .reference(URL(string: Self.base + "/vci/offers/ref1")!))
        #expect(try CredentialOfferParser.source(of: "haip-vci://credential_offer?credential_offer=\(json)") == .inline(Data(#"{"a":1}"#.utf8)))
    }

    @Test func recognizesCredentialOfferLinks() {
        #expect(CredentialOfferLink.isOffer(Self.offerLink))
        #expect(CredentialOfferLink.isOffer(" HAIP-VCI://credential_offer?credential_offer=%7B%7D "))
        #expect(!CredentialOfferLink.isOffer("haip-vp://?request_uri=https%3A%2F%2Fexample.com"))
    }

    @Test(arguments: [
        "https://example.com/not-an-offer",
        "openid-credential-offer://?foo=bar",
        "openid-credential-offer://?credential_offer_uri=http%3A%2F%2Fissuer.example.com%2Foffer",
        "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fa.example%2Fo&credential_offer=%7B%7D",
        "haip-vci://credential_offer?foo=bar",
        "haip-vci://credential_offer?credential_offer_uri=http%3A%2F%2Fa.example%2Fo",
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

    @Test func rejectsDuplicateConfigurationIDs() throws {
        let offer = TestIssuer.offerJSON(ids: ["admin", "admin"])
        #expect(throws: WalletError.notAnOffer) {
            try CredentialOfferParser.parse(json: JSONSerialization.data(withJSONObject: offer))
        }
    }

    @Test func parsesAuthorizationCodeOnlyHAIPOffer() throws {
        let offer: [String: Any] = [
            "credential_issuer": Self.base,
            "credential_configuration_ids": ["admin"],
            "grants": ["authorization_code": ["issuer_state": "example-state"]],
        ]
        let json = try String(decoding: JSONSerialization.data(withJSONObject: offer), as: UTF8.self)
        let encoded = try #require(json.addingPercentEncoding(withAllowedCharacters: .alphanumerics))
        let link = "haip-vci://credential_offer?credential_offer=\(encoded)"
        let parsed = try CredentialOfferParser.parse(json: JSONSerialization.data(withJSONObject: offer))
        #expect(parsed.grant == .authorizationCode(issuerState: "example-state", authorizationServer: nil))
        #expect(try CredentialOfferParser.source(of: link) == .inline(Data(json.utf8)))
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").isEmpty)
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

    @Test func issuedCredentialKeepsIssuerCardDesign() async throws {
        var metadata = TestIssuer.issuerMetadata()
        var configurations = metadata["credential_configurations_supported"] as! [String: Any]
        var configuration = configurations["admin"] as! [String: Any]
        var credentialMetadata = configuration["credential_metadata"] as! [String: Any]
        credentialMetadata["display"] = [[
            "name": "Admin credential", "locale": "en", "description": "A credential for administrators",
            "background_color": "#123", "text_color": "#fff",
        ]]
        configuration["credential_metadata"] = credentialMetadata
        configurations["admin"] = configuration
        metadata["credential_configurations_supported"] = configurations
        stubHappyPath(metadata: metadata)

        let service = client()
        let preview = try await service.preview(offer: Self.offerLink)
        let credential = try await service.issue(preview, transactionCode: "123456")
        #expect(credential.credentialDisplay?.backgroundColor == "#112233")
        #expect(credential.credentialDisplay?.textColor == "#FFFFFF")
        #expect(credential.credentialDisplay?.description == "A credential for administrators")
        #expect(store.items.first?.credentialDisplay == credential.credentialDisplay)
    }

    @Test func issuedCredentialStoresRenderedSVGTemplate() async throws {
        var options = TestIssuer.Options()
        options.extraPayload = ["name": "Alex & Morgan"]
        let issuer = issuer
        let signer = signer
        stubHappyPath(credential: { try issuer.sdJwt(holder: signer.publicJWK, options) })
        let template = Data(#"<svg xmlns="http://www.w3.org/2000/svg"><text>{{holder}}</text></svg>"#.utf8)
        StubURLProtocol.on("GET", TestIssuer.vct, json: [
            "vct": TestIssuer.vct,
            "claims": [["path": ["name"], "mandatory": true, "svg_id": "holder"]],
            "display": [["locale": "en", "name": "Rendered card", "rendering": [
                "svg_templates": [["uri": "data:image/svg+xml;base64,\(template.base64EncodedString())"]],
            ]]],
        ])

        let service = client()
        let preview = try await service.preview(offer: Self.offerLink)
        let credential = try await service.issue(preview, transactionCode: "123456")
        #expect(credential.credentialName == "Rendered card")
        let face = try #require(credential.credentialDisplay?.selectedSVGVariant(colorScheme: "light", contrast: "normal")?.data)
        #expect(String(data: face, encoding: .utf8)?.contains("Alex &amp; Morgan") == true)
        #expect(store.items.first?.credentialDisplay?.selectedSVGVariant(colorScheme: "light", contrast: "normal")?.data == face)
    }

    @Test func concurrentReceivesDoNotRedeemOneOfferTwice() async throws {
        stubHappyPath(offer: TestIssuer.offerJSON(txCode: false))
        let tokenURL = Self.base + "/vci/token"
        StubURLProtocol.on("POST", tokenURL) { _ in
            Thread.sleep(forTimeInterval: 0.25)
            return .init(headers: ["Content-Type": "application/json"],
                         body: Data(#"{"access_token":"AT","token_type":"Bearer","expires_in":300}"#.utf8))
        }
        let service = client()
        let preview = try await service.preview(offer: Self.offerLink)
        let first = Task { try await service.issue(preview, transactionCode: nil) }
        for _ in 0..<200 where StubURLProtocol.requests(to: tokenURL).isEmpty {
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(StubURLProtocol.requests(to: tokenURL).count == 1)
        await #expect(throws: WalletError.self) {
            try await service.issue(preview, transactionCode: nil)
        }
        _ = try await first.value
        #expect(StubURLProtocol.requests(to: tokenURL).count == 1)
    }

    @Test func unsafeConfigurationIDIsNeverShownAsTheCredentialName() async throws {
        let id = "\u{202E}\u{0007}"
        var metadata = TestIssuer.issuerMetadata()
        var configurations = metadata["credential_configurations_supported"] as! [String: Any]
        var configuration = configurations.removeValue(forKey: "admin") as! [String: Any]
        configuration.removeValue(forKey: "credential_metadata")
        metadata["credential_configurations_supported"] = [id: configuration]
        stubHappyPath(offer: TestIssuer.offerJSON(ids: [id]), metadata: metadata)

        let preview = try await client().preview(offer: Self.offerLink)
        #expect(preview.credentialName == String(TestIssuer.vct.prefix(120)))
        #expect(IssuerMetadata.sanitize("abc\u{202E}def") == "abcdef")
    }

    @Test(arguments: [
        "localhost", "printer.local", "db.internal", "127.0.0.1", "127.1", "2130706433", "10.0.0.8",
        "172.20.1.1", "192.168.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "[::1]", "[fe80::1]",
        "[fd00::1]", "[fec0::1]", "[2002:a00:8::1]", "[2001::1]",
        "[::ffff:192.168.0.1]", "[::127.0.0.1]", "[::]", "[64:ff9b::a00:1]", "[64:ff9b:1::a00:1]", "[2001:db8::1]", "[ff02::1]",
        "239.0.0.1", "255.255.255.255", "192.0.0.8", "192.0.0.255", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1",
    ])
    func rejectsNonPublicHosts(host: String) {
        #expect(throws: WalletError.self) { try WalletHTTP.requireHTTPS(URL(string: "https://\(host)/x")!, "The URL") }
    }

    @Test func acceptsPublicHosts() throws {
        for host in ["issuer.example.com", "8.8.8.8", "[2606:4700::1111]", "172.32.0.1", "192.0.1.1", "[::ffff:192.0.1.1]", "[64:ff9b::808:808]"] {
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

    @Test func rejectsMalformedAuthorizationServerList() async {
        var metadata = TestIssuer.issuerMetadata()
        metadata["authorization_servers"] = Self.base + "/vci"
        stubHappyPath(metadata: metadata)
        await #expect(throws: WalletError.invalidIssuer("The authorization server list is malformed.")) {
            try await client().preview(offer: Self.offerLink)
        }
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").isEmpty)
    }

    @Test func rejectsRequiredKeyAttestationBeforeRedeemingMultiOffer() async throws {
        var metadata = multiConfigurationMetadata()
        var configurations = try #require(metadata["credential_configurations_supported"] as? [String: Any])
        var learning = try #require(configurations["learning"] as? [String: Any])
        var proofTypes = try #require(learning["proof_types_supported"] as? [String: Any])
        var jwt = try #require(proofTypes["jwt"] as? [String: Any])
        jwt["key_attestations_required"] = ["key_storage": ["iso_18045_high"]]
        proofTypes["jwt"] = jwt
        learning["proof_types_supported"] = proofTypes
        configurations["learning"] = learning
        metadata["credential_configurations_supported"] = configurations
        stubHappyPath(offer: TestIssuer.offerJSON(ids: ["admin", "learning"]), metadata: metadata)

        await #expect(throws: WalletError.unsupportedKeyAttestation) {
            try await client().preview(offer: Self.offerLink)
        }
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").isEmpty)
    }

    @Test func acceptsEndpointsDelegatedByVerifiedMetadata() async throws {
        let authorizationServer = "https://auth.example.com/realm"
        let credentialEndpoint = "https://backend.example.com/credential"
        let nonceEndpoint = "https://backend.example.com/nonce"
        stubHappyPath(metadata: TestIssuer.issuerMetadata(
            credentialEndpoint: credentialEndpoint, nonceEndpoint: nonceEndpoint,
            servers: [authorizationServer]))
        let metadataURL = try #require(IssuerMetadata.wellKnownURL(
            for: URL(string: authorizationServer)!, suffix: "oauth-authorization-server"))
        StubURLProtocol.on("GET", metadataURL.absoluteString,
                           json: TestIssuer.serverMetadata(
                            issuer: authorizationServer, tokenEndpoint: authorizationServer + "/token"))
        let parsed = try CredentialOfferParser.parse(json: JSONSerialization.data(withJSONObject: TestIssuer.offerJSON()))
        let resolved = try await IssuerMetadata.resolve(
            offer: parsed, http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), preferredLanguages: ["en"])
        #expect(resolved.authorizationServer.absoluteString == authorizationServer)
        #expect(resolved.tokenEndpoint.absoluteString == authorizationServer + "/token")
        #expect(resolved.credentialEndpoint.absoluteString == credentialEndpoint)
        #expect(resolved.nonceEndpoint?.absoluteString == nonceEndpoint)
    }

    @Test func rejectsUnsafeAdvertisedEndpoints() async {
        for endpoint in [
            "http://backend.example.com/credential",
            "https://127.0.0.1/credential",
            "https://backend.example.com/credential#fragment",
        ] {
            stubHappyPath(metadata: TestIssuer.issuerMetadata(credentialEndpoint: endpoint))
            await #expect(throws: WalletError.self) { try await client().preview(offer: Self.offerLink) }
        }
        stubHappyPath(server: TestIssuer.serverMetadata(tokenEndpoint: "https://other.example.com/token"))
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

    @Test func acceptsSuccessfulNonceResponseWithHTTP201() async throws {
        stubHappyPath()
        StubURLProtocol.on("POST", Self.base + "/vci/nonce", json: ["c_nonce": "NONCE-201"], status: 201)
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink)
        let stored = try await client.issue(preview, transactionCode: "123456")
        let body = try #require(StubURLProtocol.body(of: Self.base + "/vci/credential"))
        let request = try #require(JSONSerialization.jsonObject(with: body) as? [String: Any])
        let proof = try #require(((request["proofs"] as? [String: Any])?["jwt"] as? [String])?.first)
        let parts = try #require(JWS.parse(proof))
        #expect(parts.payload["nonce"] as? String == "NONCE-201")
        #expect(store.items == [stored])
    }

    @Test func issuesAndStoresFromHAIPPreAuthorizedOffer() async throws {
        let root = try #require(Data(base64Encoded: IssuerX509VerifierTests.root))
        let scalar = try P256.Signing.PrivateKey(
            rawRepresentation: #require(Data(base64Encoded: IssuerX509VerifierTests.scalar)))
        var options = TestIssuer.Options()
        options.iat = Date(timeIntervalSince1970: 1_794_182_400)
        options.exp = options.iat.addingTimeInterval(3_600)
        options.signWith = scalar
        options.extraHeader = ["x5c": [IssuerX509VerifierTests.leaf]]
        var server = TestIssuer.serverMetadata()
        server["dpop_signing_alg_values_supported"] = ["ES256"]
        stubHappyPath(server: server, credential: { try issuer.sdJwt(holder: signer.publicJWK, options) })
        StubURLProtocol.on("POST", Self.base + "/vci/token", json: [
            "access_token": "AT", "token_type": "DPoP", "expires_in": 300,
        ])
        let reference = try #require((Self.base + "/vci/offers/ref1").addingPercentEncoding(withAllowedCharacters: .alphanumerics))
        let link = "haip-vci://credential_offer?credential_offer_uri=\(reference)"
        let signer = signer
        let deleted = deleted
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            makeKey: { _ in signer }, deleteKey: { deleted.value.append($0) },
            now: { Date(timeIntervalSince1970: 1_794_182_400) },
            languages: { ["en"] },
            issuerCertificateTrustSource: WalletTestIssuerX509TrustSource(
                root: root, vcts: [TestIssuer.vct]))
        let preview = try await client.preview(offer: link)
        let stored = try await client.issue(preview, transactionCode: "123456")
        #expect(store.items == [stored])
        #expect(stored.vct == TestIssuer.vct)
    }

    @Test func HAIPWithoutIssuerCertificatePolicyFailsBeforeToken() async throws {
        var server = TestIssuer.serverMetadata()
        server["dpop_signing_alg_values_supported"] = ["ES256"]
        stubHappyPath(server: server)
        let reference = try #require((Self.base + "/vci/offers/ref1")
            .addingPercentEncoding(withAllowedCharacters: .alphanumerics))
        await #expect(throws: WalletError.unsupportedIssuerCertificateTrust) {
            try await client().preview(offer: "haip-vci://credential_offer?credential_offer_uri=\(reference)")
        }
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").isEmpty)
    }

    @Test func HAIPWithoutDPoPMetadataFailsBeforeToken() async throws {
        stubHappyPath()
        let reference = try #require((Self.base + "/vci/offers/ref1")
            .addingPercentEncoding(withAllowedCharacters: .alphanumerics))
        await #expect(throws: WalletError.invalidIssuer(
            "The HAIP authorization server does not support DPoP.")) {
            try await client().preview(offer: "haip-vci://credential_offer?credential_offer_uri=\(reference)")
        }
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").isEmpty)
    }

    @Test func dpopTokenNonceAndCredentialRequestUseSameKey() async throws {
        var server = TestIssuer.serverMetadata()
        server["dpop_signing_alg_values_supported"] = ["ES256"]
        stubHappyPath(server: server)
        let tokenProofs = Box<[String]>([])
        let credentialProofs = Box<[String]>([])
        StubURLProtocol.on("POST", Self.base + "/vci/token") { request in
            if let proof = request.value(forHTTPHeaderField: "DPoP") { tokenProofs.value.append(proof) }
            if tokenProofs.value.count == 1 {
                return .init(status: 400, headers: ["DPoP-Nonce": "as-nonce", "Content-Type": "application/json"],
                             body: Data(#"{"error":"use_dpop_nonce"}"#.utf8))
            }
            return .init(headers: ["Content-Type": "application/json"],
                         body: Data(#"{"access_token":"AT","token_type":"DPoP"}"#.utf8))
        }
        StubURLProtocol.on("POST", Self.base + "/vci/nonce") { _ in
            .init(headers: ["DPoP-Nonce": "resource-nonce", "Content-Type": "application/json"],
                  body: Data(#"{"c_nonce":"NONCE-1"}"#.utf8))
        }
        let issuer = issuer
        let signer = signer
        StubURLProtocol.on("POST", Self.base + "/vci/credential") { request in
            if let proof = request.value(forHTTPHeaderField: "DPoP") { credentialProofs.value.append(proof) }
            guard let credential = try? issuer.sdJwt(holder: signer.publicJWK),
                  let body = try? JSONSerialization.data(withJSONObject: ["credentials": [["credential": credential]]])
            else { return .init(status: 500) }
            return .init(headers: ["Content-Type": "application/json"], body: body)
        }

        let client = client()
        let preview = try await client.preview(offer: Self.offerLink)
        #expect(preview.authorizationServer.absoluteString == Self.base + "/vci")
        _ = try await client.issue(preview, transactionCode: "123456")

        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").count == 2)
        #expect(tokenProofs.value.count == 2 && credentialProofs.value.count == 1)
        let first = try #require(tokenProofs.value.first.flatMap(JWS.parse))
        let second = try #require(tokenProofs.value.last.flatMap(JWS.parse))
        let credential = try #require(credentialProofs.value.first.flatMap(JWS.parse))
        #expect(first.payload["nonce"] == nil)
        #expect(second.payload["nonce"] as? String == "as-nonce")
        #expect(credential.payload["nonce"] as? String == "resource-nonce")
        #expect(credential.payload["ath"] as? String == "61RCcFlp3I2l36yPlljcaKzatbt2Nbp8xVHjiUFqw04")
        #expect((first.header["jwk"] as? [String: String]) == (credential.header["jwk"] as? [String: String]))
        #expect(first.payload["jti"] as? String != second.payload["jti"] as? String)
        #expect(second.payload["jti"] as? String != credential.payload["jti"] as? String)
        let request = try #require(StubURLProtocol.requests(to: Self.base + "/vci/credential").first)
        #expect(request.value(forHTTPHeaderField: "Authorization") == "DPoP AT")
        #expect(store.items.count == 1)
    }

    @Test func dpopResourceChallengeRetriesOnceWithFreshProof() async throws {
        var server = TestIssuer.serverMetadata()
        server["dpop_signing_alg_values_supported"] = ["ES256"]
        stubHappyPath(server: server)
        StubURLProtocol.on("POST", Self.base + "/vci/token", json: [
            "access_token": "AT", "token_type": "DPoP",
        ])
        let proofs = Box<[String]>([])
        let issuer = issuer
        let signer = signer
        StubURLProtocol.on("POST", Self.base + "/vci/credential") { request in
            if let proof = request.value(forHTTPHeaderField: "DPoP") { proofs.value.append(proof) }
            if proofs.value.count == 1 {
                return .init(
                    status: 401,
                    headers: ["WWW-Authenticate": #"DPoP error="use_dpop_nonce""#,
                              "DPoP-Nonce": "resource-challenge"],
                    body: Data())
            }
            guard let credential = try? issuer.sdJwt(holder: signer.publicJWK),
                  let body = try? JSONSerialization.data(withJSONObject: ["credentials": [["credential": credential]]])
            else { return .init(status: 500) }
            return .init(headers: ["Content-Type": "application/json"], body: body)
        }

        let client = client()
        let preview = try await client.preview(offer: Self.offerLink)
        _ = try await client.issue(preview, transactionCode: "123456")
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/credential").count == 2)
        let first = try #require(proofs.value.first.flatMap(JWS.parse))
        let second = try #require(proofs.value.last.flatMap(JWS.parse))
        #expect(first.payload["nonce"] == nil)
        #expect(second.payload["nonce"] as? String == "resource-challenge")
        #expect(first.payload["jti"] as? String != second.payload["jti"] as? String)
        #expect((first.header["jwk"] as? [String: String]) == (second.header["jwk"] as? [String: String]))
        #expect(store.items.count == 1)
    }

    @Test func repeatedDPoPResourceChallengeStopsAfterOneRetry() async throws {
        var server = TestIssuer.serverMetadata()
        server["dpop_signing_alg_values_supported"] = ["ES256"]
        stubHappyPath(server: server)
        StubURLProtocol.on("POST", Self.base + "/vci/token", json: [
            "access_token": "AT", "token_type": "DPoP",
        ])
        StubURLProtocol.on("POST", Self.base + "/vci/credential") { _ in
            .init(status: 401,
                  headers: ["WWW-Authenticate": #"DPoP error="use_dpop_nonce""#,
                            "DPoP-Nonce": "retry-nonce"], body: Data())
        }
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink)
        await #expect(throws: WalletError.self) { try await client.issue(preview, transactionCode: "123456") }
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/credential").count == 2)
        #expect(store.items.isEmpty)
    }

    @Test func bearerResponseAfterDPoPTokenRequestKeepsBearerCredentialRequest() async throws {
        var server = TestIssuer.serverMetadata()
        server["dpop_signing_alg_values_supported"] = ["ES256"]
        stubHappyPath(server: server)
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink)
        _ = try await client.issue(preview, transactionCode: "123456")
        let tokenRequest = try #require(StubURLProtocol.requests(to: Self.base + "/vci/token").first)
        let credentialRequest = try #require(StubURLProtocol.requests(to: Self.base + "/vci/credential").first)
        #expect(tokenRequest.value(forHTTPHeaderField: "DPoP") != nil)
        #expect(credentialRequest.value(forHTTPHeaderField: "Authorization") == "Bearer AT")
        #expect(credentialRequest.value(forHTTPHeaderField: "DPoP") == nil)
    }

    @Test func issuesBothConfigurationsWithOneTokenAndSeparateKeys() async throws {
        let signers = Box<[TestSigner]>([])
        let requests = Box<[[String: Any]]>([])
        let client = multiClient(signers: signers, requests: requests)
        let preview = try await client.preview(offer: Self.offerLink)
        #expect(preview.credentials.map(\.id) == ["admin", "learning"])
        #expect(preview.credentials.map(\.name) == ["Admin credential", "Learning credential"])

        // The client follows the offer order even if the caller lists selections in another order.
        let issued = try await client.issueAll(
            preview, selectedConfigurationIds: ["learning", "admin"], transactionCode: "123456")
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").count == 1)
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/nonce").count == 2)
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/credential").count == 2)
        #expect(requests.value.compactMap { $0["credential_configuration_id"] as? String } == ["admin", "learning"])
        #expect(issued.map(\.credentialConfigurationId) == ["admin", "learning"])
        #expect(issued.map(\.vct) == [TestIssuer.vct, Self.learningVct])
        #expect(Set(issued.map(\.keyTag)).count == 2)
        #expect(Set(signers.value.map { $0.publicJWK.confirmationCode }).count == 2)
        #expect(Set(store.items.map(\.id)) == Set(issued.map(\.id)))
        #expect(deleted.value.isEmpty)
    }

    @Test func issuesTwoConfigurationsAcrossDelegatedEndpoints() async throws {
        let signers = Box<[TestSigner]>([])
        let requests = Box<[[String: Any]]>([])
        let client = multiClient(signers: signers, requests: requests, delegatedEndpoints: true)
        let preview = try await client.preview(offer: Self.offerLink)
        #expect(preview.authorizationServer.absoluteString == "https://auth.example.com")
        let issued = try await client.issueAll(
            preview, selectedConfigurationIds: ["admin", "learning"], transactionCode: "123456")

        #expect(issued.count == 2 && store.items.count == 2)
        #expect(StubURLProtocol.requests(to: "https://auth.example.com/token").count == 1)
        #expect(StubURLProtocol.requests(to: "https://backend.example.com/nonce").count == 2)
        #expect(StubURLProtocol.requests(to: "https://backend.example.com/credential").count == 2)
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").isEmpty)
    }

    @Test func laterCredentialFailureKeepsEarlierSavedCredential() async throws {
        let signers = Box<[TestSigner]>([])
        let requests = Box<[[String: Any]]>([])
        let client = multiClient(signers: signers, requests: requests, rejectSecond: true)
        let preview = try await client.preview(offer: Self.offerLink)

        do {
            _ = try await client.issueAll(
                preview, selectedConfigurationIds: ["admin", "learning"], transactionCode: "123456")
            Issue.record("Expected a partial issuance error")
        } catch let partial as PartialIssuanceError {
            #expect(partial.saved.count == 1)
            #expect(partial.saved[0].credentialConfigurationId == "admin")
            #expect(partial.failedCredentialName == "Learning credential")
            #expect(store.items == partial.saved)
            #expect(deleted.value.count == 1)
            #expect(!deleted.value.contains(partial.saved[0].keyTag))
        }
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").count == 1)
        await #expect(throws: WalletError.self) {
            try await client.issueAll(preview, selectedConfigurationIds: ["learning"], transactionCode: "123456")
        }
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").count == 1)
    }

    @Test func tokenCredentialIdentifierIsUsedInsteadOfConfigurationId() async throws {
        stubHappyPath()
        StubURLProtocol.on("POST", Self.base + "/vci/token", json: [
            "access_token": "AT", "token_type": "Bearer",
            "authorization_details": [[
                "type": "openid_credential", "credential_configuration_id": "admin",
                "credential_identifiers": ["dataset-admin-1"],
            ]],
        ])
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink)
        _ = try await client.issue(preview, transactionCode: "123456")
        let data = try #require(StubURLProtocol.body(of: Self.base + "/vci/credential"))
        let body = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(body["credential_identifier"] as? String == "dataset-admin-1")
        #expect(body["credential_configuration_id"] == nil)
    }

    @Test func multipleCredentialIdentifiersIssueSeparateCredentialsAndKeys() async throws {
        stubHappyPath()
        StubURLProtocol.on("POST", Self.base + "/vci/token", json: [
            "access_token": "AT", "token_type": "Bearer",
            "authorization_details": [[
                "type": "openid_credential", "credential_configuration_id": "admin",
                "credential_identifiers": ["dataset-admin-1", "dataset-admin-2"],
            ]],
        ])
        let signers = Box<[TestSigner]>([])
        let requested = Box<[String]>([])
        let issuer = issuer
        let credentialURL = Self.base + "/vci/credential"
        let nonceURL = Self.base + "/vci/nonce"
        StubURLProtocol.on("POST", nonceURL) { _ in
            let count = StubURLProtocol.requests(to: nonceURL).count
            return .init(headers: ["Content-Type": "application/json"],
                         body: Data("{\"c_nonce\":\"NONCE-\(count)\"}".utf8))
        }
        StubURLProtocol.on("POST", credentialURL) { _ in
            guard let data = StubURLProtocol.body(of: credentialURL),
                  let body = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                  let identifier = body["credential_identifier"] as? String,
                  let proof = ((body["proofs"] as? [String: Any])?["jwt"] as? [String])?.first,
                  let parts = JWS.parse(proof),
                  let signer = signers.value.last,
                  parts.payload["nonce"] as? String == "NONCE-\(requested.value.count + 1)",
                  (parts.header["jwk"] as? [String: String]) == signer.publicJWK.proofMembers,
                  let credential = try? issuer.sdJwt(holder: signer.publicJWK)
            else { return .init(status: 400) }
            requested.value.append(identifier)
            let response = try! JSONSerialization.data(withJSONObject: ["credentials": [["credential": credential]]])
            return .init(headers: ["Content-Type": "application/json"], body: response)
        }
        let store = store
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            makeKey: { tag in
                let signer = TestSigner(tag: tag, key: P256.Signing.PrivateKey())
                signers.value.append(signer)
                return signer
            },
            deleteKey: { _ in }, now: { Date() }, languages: { ["en"] })
        let preview = try await client.preview(offer: Self.offerLink)
        let saved = try await client.issueAll(preview, selectedConfigurationIds: ["admin"], transactionCode: "123456")
        #expect(saved.count == 2)
        #expect(Set(saved.map(\.keyTag)).count == 2)
        #expect(requested.value == ["dataset-admin-1", "dataset-admin-2"])
        #expect(StubURLProtocol.requests(to: nonceURL).count == 2)
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").count == 1)
        #expect(store.items == saved)
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
        await #expect(throws: WalletError.invalidIssuer("This offer is no longer available. Scan it again.")) {
            try await client.issue(preview, transactionCode: "123456")
        }
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").count == 1)
        #expect(store.items.isEmpty && deleted.value.isEmpty)
    }

    @Test func knownWrongTransactionCodeCanBeCorrectedWithoutRescanning() async throws {
        stubHappyPath()
        let tokenURL = Self.base + "/vci/token"
        StubURLProtocol.on("POST", tokenURL, json: ["error": "invalid_grant", "error_description": "invalid tx_code"], status: 400)
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink)
        await #expect(throws: WalletError.incorrectTransactionCode) {
            try await client.issue(preview, transactionCode: "000000")
        }
        StubURLProtocol.on("POST", tokenURL, json: ["access_token": "AT", "token_type": "Bearer", "expires_in": 300])
        _ = try await client.issue(preview, transactionCode: "123456")
        #expect(StubURLProtocol.requests(to: tokenURL).count == 2)
        #expect(store.items.count == 1)
    }

    @Test func invalidRequestDoesNotImplyMissingTransactionCode() async throws {
        stubHappyPath()
        StubURLProtocol.on("POST", Self.base + "/vci/token", json: ["error": "invalid_request"], status: 400)
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink)
        await #expect(throws: WalletError.offerConsumed(
            "The authorization server rejected the token request (invalid_request).")) {
            try await client.issue(preview, transactionCode: "123456")
        }
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

    @Test func tokenServerFailureHasUnknownOutcomeAndNeverRetriesCode() async throws {
        stubHappyPath()
        // An OAuth-looking body on a server failure must not override the uncertain status.
        StubURLProtocol.on("POST", Self.base + "/vci/token", json: ["error": "invalid_grant"], status: 500)
        let client = client()
        let preview = try await client.preview(offer: Self.offerLink)
        await #expect(throws: WalletError.offerConsumed("The token request outcome is unknown (HTTP 500).")) {
            try await client.issue(preview, transactionCode: "123456")
        }
        StubURLProtocol.on("POST", Self.base + "/vci/token", json: ["access_token": "AT", "token_type": "Bearer", "expires_in": 300])
        await #expect(throws: WalletError.invalidIssuer("This offer is no longer available. Scan it again.")) {
            try await client.issue(preview, transactionCode: "123456")
        }
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").count == 1)
        #expect(store.items.isEmpty)
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

nonisolated struct WalletTestIssuerX509TrustSource: IssuerCertificateTrustSource {
    let root: Data
    let vcts: Set<String>

    func supports(issuer: URL, vct: String) -> Bool {
        issuer.absoluteString == TestIssuer.base && vcts.contains(vct)
    }

    func trustedRoots(for chainDER: [Data], issuer: URL, vct: String) async throws -> [Data] {
        guard supports(issuer: issuer, vct: vct) else {
            throw WalletError.invalidIssuer("No test issuer certificate trust policy.")
        }
        return [root]
    }
}

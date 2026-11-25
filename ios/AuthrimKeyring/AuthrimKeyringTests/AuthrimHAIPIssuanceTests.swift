import CryptoKit
import Foundation
import Testing
@testable import AuthrimKeyring

nonisolated private struct HAIPTestProvider: WalletAttestationProvider {
    func supports(issuer: URL) -> Bool { issuer.absoluteString == TestIssuer.base }
    func attestation(for clientKey: PublicJWK, issuer: URL) async throws -> WalletClientAttestation {
        WalletClientAttestation(jwt: "stub-wallet-attestation", clientID: "keyring-ios")
    }
}

nonisolated private struct HAIPKeyProvider: KeyAttestationProvider {
    let scalar: Data
    func supports(issuer: URL) -> Bool { issuer.absoluteString == TestIssuer.base }
    func attestation(for holderKey: PublicJWK, nonce: String?, issuer: URL) async throws -> String {
        guard let nonce else { throw WalletError.unsupportedKeyAttestation }
        let signer = try P256.Signing.PrivateKey(rawRepresentation: scalar)
        let now = Int(Date().timeIntervalSince1970)
        return try JWS.make(
            header: ["alg": "ES256", "typ": "key-attestation+jwt", "x5c": [KeyAttestationVerifierTests.leaf]],
            payload: ["iat": now - 10, "exp": now + 3_600, "nonce": nonce,
                      "attested_keys": [holderKey.proofMembers],
                      "key_storage": ["iso_18045_high"], "user_authentication": ["iso_18045_high"]]
        ) { try signer.signature(for: $0).rawRepresentation }
    }
}

nonisolated private struct HAIPKeyTrust: KeyAttestationTrustSource {
    let root: Data
    func trustedRoots(for attestation: String, issuer: URL) async throws -> [Data] { [root] }
}

@MainActor
private final class HAIPBrowser: AuthorizationBrowser {
    let parURL: String
    var openedURL: URL?
    var redirectSeen: URL?
    init(parURL: String) { self.parURL = parURL }
    func authorize(_ url: URL, redirectURI: URL) async throws -> URL {
        openedURL = url
        redirectSeen = redirectURI
        let body = String(decoding: StubURLProtocol.body(of: parURL) ?? Data(), as: UTF8.self)
        let state = URLComponents(string: "https://x.test/?" + body)?.queryItems?
            .first(where: { $0.name == "state" })?.value ?? ""
        let iss = TestIssuer.base.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? ""
        return URL(string: redirectURI.absoluteString + "?code=AUTH-CODE&state=\(state)&iss=\(iss)")!
    }
}

/// The admin credential over HAIP, with the real validators and an Authrim-shaped fake OP: the OP is
/// the authorization server at the issuer root, the credential carries `x5c` `[leaf, issuing CA]`
/// (root excluded), and the issuer's own key set is never fetched.
extension StubbedNetworkTests {
@Suite(.serialized)
struct AuthrimHAIPIssuanceTests {
    static let base = TestIssuer.base
    static let redirect = URL(string: "https://keyring.example.net/oauth/callback")!

    init() { StubURLProtocol.reset() }

    private struct Harness {
        let client: OpenID4VCIClient
        let browser: HAIPBrowser
        let store: MemoryStore
        let signers: Box<[TestSigner]>
        let deleted: Box<[String]>
        let offer: String
    }

    private func stubServer(attestMethod: Bool = true, credentialNonceChallenge: Bool = false) throws {
        let base = Self.base
        let issuer = TestIssuer()
        var metadata = TestIssuer.issuerMetadata(servers: [base])
        var configurations = try #require(metadata["credential_configurations_supported"] as? [String: Any])
        var admin = try #require(configurations["admin"] as? [String: Any])
        admin["scope"] = "authrim_admin_credential"
        admin["proof_types_supported"] = ["jwt": [
            "proof_signing_alg_values_supported": ["ES256"],
            "key_attestations_required": ["key_storage": ["iso_18045_high"]],
        ]]
        configurations["admin"] = admin
        metadata["credential_configurations_supported"] = configurations
        StubURLProtocol.on("GET", base + "/.well-known/openid-credential-issuer", json: metadata)
        StubURLProtocol.on("GET", base + "/.well-known/oauth-authorization-server", json: [
            "issuer": base, "token_endpoint": base + "/token",
            "authorization_endpoint": base + "/authorize",
            "pushed_authorization_request_endpoint": base + "/par",
            "grant_types_supported": ["authorization_code"], "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": true,
            "dpop_signing_alg_values_supported": ["ES256"],
            "token_endpoint_auth_methods_supported": attestMethod ? ["attest_jwt_client_auth"] : ["none"],
        ])
        StubURLProtocol.on("POST", base + "/par", json: ["request_uri": "urn:par:1", "expires_in": 90], status: 201)
        StubURLProtocol.on("POST", base + "/token", json: ["access_token": "AT", "token_type": "DPoP"])
        StubURLProtocol.on("POST", base + "/nonce", json: ["c_nonce": "NONCE-1"])
        // The credential endpoint lives at `/vci/credential`, the nonce endpoint at `/vci/nonce`.
        StubURLProtocol.on("POST", base + "/vci/nonce", json: ["c_nonce": "NONCE-1"])
        let scalar = try #require(Data(base64Encoded: AuthrimPKIFixture.leafScalar))
        let leaf = try P256.Signing.PrivateKey(rawRepresentation: scalar)
        let calls = Box(0)
        StubURLProtocol.on("POST", base + "/vci/credential") { request in
            calls.value += 1
            if credentialNonceChallenge && calls.value == 1 {
                return .init(status: 401, headers: ["WWW-Authenticate": #"DPoP error="use_dpop_nonce""#,
                                                    "DPoP-Nonce": "SERVER-NONCE"], body: Data())
            }
            guard let body = StubURLProtocol.body(of: base + "/vci/credential"),
                  let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
                  let proofText = ((object["proofs"] as? [String: Any])?["jwt"] as? [String])?.first,
                  let proof = JWS.parse(proofText), let jwk = proof.header["jwk"] as? [String: Any],
                  let holder = PublicJWK(from: jwk) else { return .init(status: 400) }
            var options = TestIssuer.Options()
            options.signWith = leaf
            options.extraHeader = ["x5c": [AuthrimPKIFixture.leaf, AuthrimPKIFixture.issuingCA]]
            guard let credential = try? issuer.sdJwt(holder: holder, options),
                  let data = try? JSONSerialization.data(withJSONObject: ["credentials": [["credential": credential]]])
            else { return .init(status: 500) }
            return .init(headers: ["Content-Type": "application/json"], body: data)
        }
    }

    @MainActor
    private func harness(roots: [Data]? = nil, redirect: URL = AuthrimHAIPIssuanceTests.redirect) throws -> Harness {
        let rootDER = try #require(Data(base64Encoded: AuthrimPKIFixture.root))
        let pinned = roots ?? [rootDER]
        let keyScalar = try #require(Data(base64Encoded: KeyAttestationVerifierTests.scalar))
        let keyRoot = try #require(Data(base64Encoded: KeyAttestationVerifierTests.root))
        let store = MemoryStore()
        let signers = Box<[TestSigner]>([])
        let deleted = Box<[String]>([])
        let browser = HAIPBrowser(parURL: Self.base + "/par")
        let vct = TestIssuer.vct
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            makeKey: { tag in
                let signer = TestSigner(tag: tag, key: P256.Signing.PrivateKey())
                signers.value.append(signer)
                return signer
            },
            deleteKey: { deleted.value.append($0) },
            now: { Date() }, languages: { ["en"] },
            keyAttestationProvider: HAIPKeyProvider(scalar: keyScalar),
            keyAttestationTrustSource: HAIPKeyTrust(root: keyRoot),
            walletAttestationProvider: HAIPTestProvider(),
            issuerCertificateTrustSource: AuthrimCATrustSource(roots: pinned, vcts: [vct]),
            authorizationBrowser: browser, redirectURI: redirect)
        let offer: [String: Any] = [
            "credential_issuer": Self.base, "credential_configuration_ids": ["admin"],
            "grants": ["authorization_code": ["authorization_server": Self.base]],
        ]
        let json = String(decoding: try JSONSerialization.data(withJSONObject: offer), as: UTF8.self)
        let encoded = try #require(json.addingPercentEncoding(withAllowedCharacters: .alphanumerics))
        return Harness(client: client, browser: browser, store: store, signers: signers, deleted: deleted,
                       offer: "haip-vci://?credential_offer=\(encoded)")
    }

    private func fields(_ url: String) throws -> [String: String] {
        let data = try #require(StubURLProtocol.body(of: url))
        let items = URLComponents(string: "https://x.test/?" + String(decoding: data, as: UTF8.self))?.queryItems ?? []
        return Dictionary(uniqueKeysWithValues: items.compactMap { item in item.value.map { (item.name, $0) } })
    }

    @Test @MainActor func issuesAdminCredentialWithAuthrimShapedHAIPFlow() async throws {
        try stubServer()
        let h = try harness()
        let preview = try await h.client.preview(offer: h.offer)
        #expect(preview.authorizationRequired)
        let stored = try await h.client.issue(preview, transactionCode: nil)

        // PAR: attestation client authentication, DPoP, PKCE, scope only, https redirect.
        let par = try fields(Self.base + "/par")
        #expect(par["client_id"] == "keyring-ios")
        #expect(par["redirect_uri"] == Self.redirect.absoluteString)
        #expect(par["scope"] == "authrim_admin_credential")
        #expect(par["authorization_details"] == nil)
        #expect(par["issuer_state"] == nil)
        #expect(par["resource"] == Self.base)
        #expect(par["code_challenge_method"] == "S256")
        let parRequest = try #require(StubURLProtocol.requests(to: Self.base + "/par").first)
        #expect(parRequest.value(forHTTPHeaderField: "OAuth-Client-Attestation") == "stub-wallet-attestation")
        let popText = try #require(parRequest.value(forHTTPHeaderField: "OAuth-Client-Attestation-PoP"))
        let pop = try #require(JWS.parse(popText))
        #expect(pop.payload["iss"] as? String == "keyring-ios")
        #expect(pop.payload["aud"] as? String == Self.base)
        // Key continuity: the PoP is signed by the key that signs every DPoP proof of the session.
        let parDPoPText = try #require(parRequest.value(forHTTPHeaderField: "DPoP"))
        let parDPoP = try #require(JWS.parse(parDPoPText))
        let dpopMembers = try #require(parDPoP.header["jwk"] as? [String: Any])
        let dpopJWK = try #require(PublicJWK(from: dpopMembers))
        let dpopKey = try #require(dpopJWK.cryptoKey)
        #expect(JWS.verifyES256(pop, with: dpopKey))
        #expect(JWS.verifyES256(parDPoP, with: dpopKey))
        #expect(parRequest.value(forHTTPHeaderField: "DPoP") != nil)
        #expect(h.browser.redirectSeen == Self.redirect)

        // Token: code, verifier, the same redirect, attestation again.
        let token = try fields(Self.base + "/token")
        #expect(token["grant_type"] == "authorization_code")
        #expect(token["redirect_uri"] == Self.redirect.absoluteString)
        let verifier = try #require(token["code_verifier"])
        #expect(par["code_challenge"] == AuthorizationCodeFlow.challenge(for: verifier))
        let tokenRequest = try #require(StubURLProtocol.requests(to: Self.base + "/token").first)
        #expect(tokenRequest.value(forHTTPHeaderField: "OAuth-Client-Attestation") == "stub-wallet-attestation")

        // Credential: DPoP-bound request, key attestation in the proof, no legacy `proof`.
        let credentialRequest = try #require(StubURLProtocol.requests(to: Self.base + "/vci/credential").first)
        #expect(credentialRequest.value(forHTTPHeaderField: "Authorization") == "DPoP AT")
        let dpopText = try #require(credentialRequest.value(forHTTPHeaderField: "DPoP"))
        let dpop = try #require(JWS.parse(dpopText))
        #expect(dpop.payload["ath"] as? String == Base64URL.encode(Data(SHA256.hash(data: Data("AT".utf8)))))
        #expect(dpop.payload["htu"] as? String == Self.base + "/vci/credential")
        let credentialMembers = try #require(dpop.header["jwk"] as? [String: Any])
        let credentialJWK = try #require(PublicJWK(from: credentialMembers))
        #expect(credentialJWK.isSameKey(as: dpopJWK))
        #expect(JWS.verifyES256(dpop, with: dpopKey))
        let bodyData = try #require(StubURLProtocol.body(of: Self.base + "/vci/credential"))
        let body = try #require(JSONSerialization.jsonObject(with: bodyData) as? [String: Any])
        #expect(body["proof"] == nil)
        let proofText = try #require(((body["proofs"] as? [String: Any])?["jwt"] as? [String])?.first)
        let proof = try #require(JWS.parse(proofText))
        #expect(proof.header["key_attestation"] is String)
        #expect(proof.payload["nonce"] as? String == "NONCE-1")

        // Stored: verified through the x5c chain (the issuer key set was never fetched).
        #expect(StubURLProtocol.requests(to: Self.base + "/.well-known/jwt-vc-issuer").isEmpty)
        #expect(h.store.items == [stored])
        #expect(stored.keyTag == h.signers.value.last?.tag)
        #expect(h.deleted.value.isEmpty)
    }

    @Test @MainActor func retriesCredentialRequestOnceWithServerDPoPNonce() async throws {
        try stubServer(credentialNonceChallenge: true)
        let h = try harness()
        let preview = try await h.client.preview(offer: h.offer)
        _ = try await h.client.issue(preview, transactionCode: nil)
        let requests = StubURLProtocol.requests(to: Self.base + "/vci/credential")
        #expect(requests.count == 2)
        let secondText = try #require(requests[1].value(forHTTPHeaderField: "DPoP"))
        let second = try #require(JWS.parse(secondText))
        #expect(second.payload["nonce"] as? String == "SERVER-NONCE")
    }

    @Test @MainActor func refusesHAIPOfferWithoutPinnedAuthrimRoot() async throws {
        try stubServer()
        let h = try harness(roots: [])
        await #expect(throws: WalletError.unsupportedIssuerCertificateTrust) {
            _ = try await h.client.preview(offer: h.offer)
        }
        #expect(StubURLProtocol.requests(to: Self.base + "/par").isEmpty)
    }

    @Test @MainActor func refusesCredentialUnderAnotherRootAndDeletesTheKey() async throws {
        try stubServer()
        let other = try #require(Data(base64Encoded: IssuerX509VerifierTests.root))
        let h = try harness(roots: [other])
        let preview = try await h.client.preview(offer: h.offer)
        await #expect(throws: WalletError.self) { _ = try await h.client.issue(preview, transactionCode: nil) }
        #expect(h.store.items.isEmpty)
        #expect(!h.signers.value.isEmpty && Set(h.deleted.value) == Set(h.signers.value.map(\.tag)))
    }

    @Test @MainActor func refusesServerWithoutAttestationClientAuthentication() async throws {
        try stubServer(attestMethod: false)
        let h = try harness()
        await #expect(throws: WalletError.self) { _ = try await h.client.preview(offer: h.offer) }
        #expect(StubURLProtocol.requests(to: Self.base + "/par").isEmpty)
    }

    @Test func httpsRedirectIsMatchedExactly() throws {
        let issuer = try #require(URL(string: Self.base))
        let good = try #require(URL(string: Self.redirect.absoluteString + "?code=C&state=S&iss=https%3A%2F%2Fissuer.example.com"))
        #expect(try AuthorizationCodeFlow.code(
            from: good, state: "S", authorizationServer: issuer, redirectURI: Self.redirect) == "C")
        for text in [
            "https://keyring.example.net/oauth/%63allback?code=C&state=S&iss=https%3A%2F%2Fissuer.example.com",
            "https://keyring.example.net/oauth/callback/?code=C&state=S&iss=https%3A%2F%2Fissuer.example.com",
            "https://keyring.example.net/other?code=C&state=S&iss=https%3A%2F%2Fissuer.example.com",
            "https://evil.example.net/oauth/callback?code=C&state=S&iss=https%3A%2F%2Fissuer.example.com",
            "https://keyring.example.net:8443/oauth/callback?code=C&state=S&iss=https%3A%2F%2Fissuer.example.com",
            "com.authrim.keyring://oauth/callback?code=C&state=S&iss=https%3A%2F%2Fissuer.example.com",
        ] {
            #expect(throws: WalletError.self) {
                try AuthorizationCodeFlow.code(
                    from: URL(string: text)!, state: "S", authorizationServer: issuer, redirectURI: Self.redirect)
            }
        }
    }

    @Test func redirectURIValidation() {
        for text in ["https://keyring.example.net/oauth/callback", "com.authrim.keyring://oauth/callback"] {
            #expect(AuthorizationCodeFlow.isValidRedirect(URL(string: text)!))
        }
        for text in ["http://keyring.example.net/oauth/callback", "https://keyring.example.net/",
                     "https://keyring.example.net/cb?x=1", "https://keyring.example.net:444/cb",
                     "https://u:p@keyring.example.net/cb", "https://keyring.example.net/cb#f", "myapp://cb/x"] {
            #expect(!AuthorizationCodeFlow.isValidRedirect(URL(string: text)!), Comment(rawValue: text))
        }
    }
}
}

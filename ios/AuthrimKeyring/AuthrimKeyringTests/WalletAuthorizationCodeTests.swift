import CryptoKit
import Foundation
import Testing
@testable import AuthrimKeyring

private struct AuthorizationTestProvider: WalletAttestationProvider {
    func supports(issuer: URL) -> Bool { issuer.absoluteString == TestIssuer.base }
    func attestation(for clientKey: PublicJWK, issuer: URL) async throws -> WalletClientAttestation {
        WalletClientAttestation(jwt: "verified-test-attestation", clientID: "wallet.test")
    }
}

@MainActor
private final class AuthorizationTestBrowser: AuthorizationBrowser {
    let callback: (URL) throws -> URL
    init(_ callback: @escaping (URL) throws -> URL) { self.callback = callback }
    func authorize(_ url: URL, callbackScheme: String) async throws -> URL {
        try callback(url)
    }
}

private struct AuthorizationPreviewTrust: IssuerCertificateTrustSource {
    func supports(issuer: URL, vct: String) -> Bool {
        issuer.absoluteString == TestIssuer.base && vct == TestIssuer.vct
    }
    func trustedRoots(for chainDER: [Data], issuer: URL, vct: String) async throws -> [Data] { [] }
}

extension StubbedNetworkTests {
@Suite(.serialized)
struct WalletAuthorizationCodeTests {
    let issuer = TestIssuer()
    let holder = TestSigner(tag: "com.authrim.keyring.vc.holder.authorization-test", key: P256.Signing.PrivateKey())
    let store = MemoryStore()
    let parURL = TestIssuer.base + "/vci/par"
    let tokenURL = TestIssuer.base + "/vci/token"

    init() { StubURLProtocol.reset() }

    private func offerLink(
        scheme: String = "openid-credential-offer", configurationIds: [String] = ["admin"],
        authorizationServer: String? = nil
    ) throws -> String {
        var grant = ["issuer_state": "ISSUER-STATE"]
        if let authorizationServer { grant["authorization_server"] = authorizationServer }
        let offer: [String: Any] = [
            "credential_issuer": TestIssuer.base,
            "credential_configuration_ids": configurationIds,
            "grants": ["authorization_code": grant],
        ]
        let json = try JSONSerialization.data(withJSONObject: offer)
        return scheme + "://credential_offer?credential_offer=" +
            String(decoding: json, as: UTF8.self).addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
    }

    private func setup(
        parStatus: Int = 201,
        parBody: [String: Any] = ["request_uri": "urn:example:request:1", "expires_in": 90],
        supportsAuthorizationDetails: Bool = false
    ) {
        let base = TestIssuer.base
        StubURLProtocol.on("GET", base + "/.well-known/openid-credential-issuer", json: TestIssuer.issuerMetadata())
        var metadata = TestIssuer.serverMetadata()
        metadata["grant_types_supported"] = ["authorization_code"]
        metadata["response_types_supported"] = ["code"]
        metadata["code_challenge_methods_supported"] = ["S256"]
        metadata["authorization_response_iss_parameter_supported"] = true
        metadata["authorization_endpoint"] = base + "/vci/authorize"
        metadata["pushed_authorization_request_endpoint"] = parURL
        metadata["dpop_signing_alg_values_supported"] = ["ES256"]
        metadata["token_endpoint_auth_methods_supported"] = ["attest_jwt_client_auth"]
        if supportsAuthorizationDetails {
            metadata["authorization_details_types_supported"] = ["openid_credential"]
        }
        StubURLProtocol.on("GET", base + "/.well-known/oauth-authorization-server/vci", json: metadata)
        StubURLProtocol.on("POST", parURL, json: parBody, status: parStatus)
        StubURLProtocol.on("POST", tokenURL, json: ["access_token": "AT", "token_type": "DPoP"])
        StubURLProtocol.on("POST", base + "/vci/nonce", json: ["c_nonce": "NONCE"])
        StubURLProtocol.on("GET", base + "/.well-known/jwt-vc-issuer", json: issuer.jwks())
        let issuer = issuer, holder = holder
        StubURLProtocol.on("POST", base + "/vci/credential") { _ in
            let credential = try! issuer.sdJwt(holder: holder.publicJWK)
            return .init(headers: ["Content-Type": "application/json"], body:
                try! JSONSerialization.data(withJSONObject: ["credentials": [["credential": credential]]]))
        }
    }

    private func form(_ url: String) throws -> [String: String] {
        let data = try #require(StubURLProtocol.body(of: url))
        let components = try #require(URLComponents(string: "https://example.com/?" + String(decoding: data, as: UTF8.self)))
        return Dictionary(uniqueKeysWithValues: (components.queryItems ?? []).compactMap { item in
            item.value.map { (item.name, $0) }
        })
    }

    @MainActor
    private func approvingBrowser() -> AuthorizationTestBrowser {
        let parURL = parURL
        return AuthorizationTestBrowser { _ in
            let body = StubURLProtocol.body(of: parURL)!
            let fields = URLComponents(string: "https://example.com/?" + String(decoding: body, as: UTF8.self))!.queryItems!
            let state = fields.first(where: { $0.name == "state" })!.value!
            let callback = AuthorizationCodeFlow.redirectURI.absoluteString +
                "?code=AUTH-CODE&state=\(state)&iss=" +
                (TestIssuer.base + "/vci").addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
            return URL(string: callback)!
        }
    }

    @Test func authorizesWithPARPKCEAndSavesCredential() async throws {
        setup()
        let state = Box("")
        let openedURL = Box<URL?>(nil)
        let parURL = parURL
        let browser = AuthorizationTestBrowser { url in
            openedURL.value = url
            let body = StubURLProtocol.body(of: parURL)!
            let fields = URLComponents(string: "https://example.com/?" + String(decoding: body, as: UTF8.self))!.queryItems!
            state.value = fields.first(where: { $0.name == "state" })!.value!
            let callback = AuthorizationCodeFlow.redirectURI.absoluteString +
                "?code=AUTH-CODE&state=\(state.value)&iss=" +
                TestIssuer.base.appending("/vci").addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
            return URL(string: callback)!
        }
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            makeKey: { _ in holder }, deleteKey: { _ in },
            now: { Date() }, languages: { ["en"] },
            walletAttestationProvider: AuthorizationTestProvider(), authorizationBrowser: browser)
        let preview = try await client.preview(offer: offerLink())
        #expect(preview.authorizationRequired)
        #expect(preview.transactionCode == nil)

        let saved = try await client.issue(preview, transactionCode: nil)
        #expect(store.items == [saved])
        #expect(StubURLProtocol.requests(to: parURL).count == 1)
        #expect(StubURLProtocol.requests(to: tokenURL).count == 1)
        #expect(openedURL.value?.host == URL(string: TestIssuer.base)?.host)
        #expect(openedURL.value?.path == "/vci/authorize")
        let openedItems = URLComponents(url: openedURL.value!, resolvingAgainstBaseURL: false)?.queryItems ?? []
        #expect(Set(openedItems.map(\.name)) == ["client_id", "request_uri"])
        #expect(openedItems.first(where: { $0.name == "request_uri" })?.value == "urn:example:request:1")

        let fields = try form(parURL)
        #expect(fields["response_type"] == "code")
        #expect(fields["client_id"] == "wallet.test")
        #expect(fields["redirect_uri"] == AuthorizationCodeFlow.redirectURI.absoluteString)
        #expect(fields["scope"] == "admin")
        #expect(fields["resource"] == TestIssuer.base)
        #expect(fields["issuer_state"] == "ISSUER-STATE")
        #expect(fields["code_challenge_method"] == "S256")
        #expect(fields["state"]?.count == 43)
        let token = try form(tokenURL)
        #expect(token["grant_type"] == "authorization_code")
        #expect(token["code"] == "AUTH-CODE")
        #expect(token["client_id"] == "wallet.test")
        #expect(token["redirect_uri"] == fields["redirect_uri"])
        #expect(token["resource"] == TestIssuer.base)
        let codeVerifier = try #require(token["code_verifier"])
        #expect(fields["code_challenge"] == AuthorizationCodeFlow.challenge(for: codeVerifier))
        let parRequest = try #require(StubURLProtocol.requests(to: parURL).first)
        let tokenRequest = try #require(StubURLProtocol.requests(to: tokenURL).first)
        #expect(parRequest.value(forHTTPHeaderField: "OAuth-Client-Attestation") == "verified-test-attestation")
        #expect(tokenRequest.value(forHTTPHeaderField: "OAuth-Client-Attestation") == "verified-test-attestation")
        let parProof = try #require(parRequest.value(forHTTPHeaderField: "DPoP"))
        let tokenProof = try #require(tokenRequest.value(forHTTPHeaderField: "DPoP"))
        let parDPoP = try #require(JWS.parse(parProof))
        let tokenDPoP = try #require(JWS.parse(tokenProof))
        #expect((parDPoP.header["jwk"] as? [String: String]) == (tokenDPoP.header["jwk"] as? [String: String]))
        #expect((parDPoP.payload["jti"] as? String) != (tokenDPoP.payload["jti"] as? String))
    }

    @Test func callbackRequiresExactRedirectStateAndIssuer() throws {
        let redirect = AuthorizationCodeFlow.redirectURI.absoluteString
        let issuer = URL(string: TestIssuer.base + "/vci")!
        let good = URL(string: redirect + "?code=C&state=S&iss=https%3A%2F%2Fissuer.example.com%2Fvci")!
        #expect(try AuthorizationCodeFlow.code(from: good, state: "S", authorizationServer: issuer) == "C")
        for url in [
            redirect + "?code=C&state=wrong&iss=https%3A%2F%2Fissuer.example.com%2Fvci",
            redirect + "?code=C&state=S&iss=https%3A%2F%2Fevil.example.com",
            redirect + "?code=C&state=S&state=S&iss=https%3A%2F%2Fissuer.example.com%2Fvci",
            redirect + "?code=C&code=D&state=S&iss=https%3A%2F%2Fissuer.example.com%2Fvci",
            redirect + "?code=C&state=S&iss=https%3A%2F%2Fissuer.example.com%2Fvci&iss=https%3A%2F%2Fissuer.example.com%2Fvci",
            "com.authrim.keyring://evil/callback?code=C&state=S&iss=https%3A%2F%2Fissuer.example.com%2Fvci",
        ] {
            #expect(throws: WalletError.self) {
                try AuthorizationCodeFlow.code(from: URL(string: url)!, state: "S", authorizationServer: issuer)
            }
        }
        let denied = URL(string: redirect + "?error=access_denied&state=S&iss=https%3A%2F%2Fissuer.example.com%2Fvci")!
        #expect(throws: WalletError.authorizationDenied) {
            try AuthorizationCodeFlow.code(from: denied, state: "S", authorizationServer: issuer)
        }
    }

    @Test func authorizationURLRetainsEndpointQueryWithoutDuplicatingOAuthParameters() throws {
        let endpoint = try #require(URL(string: TestIssuer.base + "/vci/authorize?tenant=a%2Bb"))
        let url = try AuthorizationCodeFlow.authorizationURL(
            endpoint: endpoint, clientID: "wallet.test", requestURI: "urn:example:request:1")
        let items = try #require(URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems)
        #expect(items.map(\.name) == ["tenant", "client_id", "request_uri"])
        #expect(items.first?.value == "a+b")
        #expect(items.last?.value == "urn:example:request:1")
        let duplicate = try #require(URL(string: TestIssuer.base + "/vci/authorize?client_id=other"))
        #expect(throws: WalletError.self) {
            try AuthorizationCodeFlow.authorizationURL(
                endpoint: duplicate, clientID: "wallet.test", requestURI: "urn:example:request:1")
        }
    }

    @Test func authorizationCodeOfferRequiresCredentialScope() async throws {
        setup()
        var metadata = TestIssuer.issuerMetadata()
        var configurations = metadata["credential_configurations_supported"] as! [String: Any]
        var admin = configurations["admin"] as! [String: Any]
        admin.removeValue(forKey: "scope")
        configurations["admin"] = admin
        metadata["credential_configurations_supported"] = configurations
        StubURLProtocol.on("GET", TestIssuer.base + "/.well-known/openid-credential-issuer", json: metadata)
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            walletAttestationProvider: AuthorizationTestProvider())
        await #expect(throws: WalletError.self) { try await client.preview(offer: offerLink()) }
        #expect(StubURLProtocol.requests(to: parURL).isEmpty)
    }

    @Test func authorizationDetailsRequestSupportsCredentialsWithoutScope() async throws {
        setup(supportsAuthorizationDetails: true)
        var metadata = TestIssuer.issuerMetadata()
        var configurations = metadata["credential_configurations_supported"] as! [String: Any]
        var admin = configurations["admin"] as! [String: Any]
        admin.removeValue(forKey: "scope")
        configurations["admin"] = admin
        metadata["credential_configurations_supported"] = configurations
        StubURLProtocol.on("GET", TestIssuer.base + "/.well-known/openid-credential-issuer", json: metadata)
        let browser = AuthorizationTestBrowser { _ in throw WalletError.authorizationDenied }
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            walletAttestationProvider: AuthorizationTestProvider(), authorizationBrowser: browser)
        let preview = try await client.preview(offer: offerLink())
        await #expect(throws: WalletError.authorizationDenied) {
            try await client.issue(preview, transactionCode: nil)
        }
        let fields = try form(parURL)
        #expect(fields["scope"] == nil)
        let detailsData = try #require(fields["authorization_details"]?.data(using: .utf8))
        let details = try #require(JSONSerialization.jsonObject(with: detailsData) as? [[String: Any]])
        #expect(details.count == 1)
        #expect(details[0]["type"] as? String == "openid_credential")
        #expect(details[0]["credential_configuration_id"] as? String == "admin")
        #expect(details[0]["locations"] as? [String] == [TestIssuer.base])
        #expect(StubURLProtocol.requests(to: tokenURL).isEmpty)
    }

    @Test func duplicateCredentialScopesAreRequestedOnce() async throws {
        setup()
        var metadata = TestIssuer.issuerMetadata()
        var configurations = metadata["credential_configurations_supported"] as! [String: Any]
        configurations["learning"] = configurations["admin"]
        metadata["credential_configurations_supported"] = configurations
        StubURLProtocol.on("GET", TestIssuer.base + "/.well-known/openid-credential-issuer", json: metadata)
        let browser = AuthorizationTestBrowser { _ in throw WalletError.authorizationDenied }
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            walletAttestationProvider: AuthorizationTestProvider(), authorizationBrowser: browser)
        let preview = try await client.preview(offer: offerLink(configurationIds: ["admin", "learning"]))
        #expect(preview.credentials.count == 2)
        await #expect(throws: WalletError.authorizationDenied) {
            try await client.issueAll(
                preview, selectedConfigurationIds: ["admin", "learning"], transactionCode: nil)
        }
        #expect(try form(parURL)["scope"] == "admin")
    }

    @Test func reducedTokenScopeCannotStartCredentialIssuance() async throws {
        setup()
        StubURLProtocol.on("POST", tokenURL, json: [
            "access_token": "AT", "token_type": "DPoP", "scope": "unrelated",
        ])
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            walletAttestationProvider: AuthorizationTestProvider(),
            authorizationBrowser: approvingBrowser())
        let preview = try await client.preview(offer: offerLink())
        await #expect(throws: WalletError.offerConsumed(
            "The token response does not authorize every selected credential scope.")) {
            try await client.issue(preview, transactionCode: nil)
        }
        #expect(StubURLProtocol.requests(to: TestIssuer.base + "/vci/credential").isEmpty)
    }

    @Test func authorizationDetailsMustBeReturnedByTokenEndpoint() async throws {
        setup(supportsAuthorizationDetails: true)
        var metadata = TestIssuer.issuerMetadata()
        var configurations = metadata["credential_configurations_supported"] as! [String: Any]
        var admin = configurations["admin"] as! [String: Any]
        admin.removeValue(forKey: "scope")
        configurations["admin"] = admin
        metadata["credential_configurations_supported"] = configurations
        StubURLProtocol.on("GET", TestIssuer.base + "/.well-known/openid-credential-issuer", json: metadata)
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            walletAttestationProvider: AuthorizationTestProvider(),
            authorizationBrowser: approvingBrowser())
        let preview = try await client.preview(offer: offerLink())
        await #expect(throws: WalletError.offerConsumed(
            "The token response omits the requested authorization details.")) {
            try await client.issue(preview, transactionCode: nil)
        }
        #expect(StubURLProtocol.requests(to: TestIssuer.base + "/vci/credential").isEmpty)
    }

    @Test func authorizationDetailsIdentifierCompletesIssuance() async throws {
        setup(supportsAuthorizationDetails: true)
        var metadata = TestIssuer.issuerMetadata()
        var configurations = metadata["credential_configurations_supported"] as! [String: Any]
        var admin = configurations["admin"] as! [String: Any]
        admin.removeValue(forKey: "scope")
        configurations["admin"] = admin
        metadata["credential_configurations_supported"] = configurations
        StubURLProtocol.on("GET", TestIssuer.base + "/.well-known/openid-credential-issuer", json: metadata)
        StubURLProtocol.on("POST", tokenURL, json: [
            "access_token": "AT", "token_type": "DPoP",
            "authorization_details": [[
                "type": "openid_credential",
                "credential_configuration_id": "admin",
                "credential_identifiers": ["dataset-1"],
            ]],
        ])
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            makeKey: { _ in holder }, deleteKey: { _ in },
            walletAttestationProvider: AuthorizationTestProvider(),
            authorizationBrowser: approvingBrowser())
        let preview = try await client.preview(offer: offerLink())
        let saved = try await client.issue(preview, transactionCode: nil)
        #expect(store.items == [saved])
        let credentialURL = TestIssuer.base + "/vci/credential"
        let body = try #require(StubURLProtocol.body(of: credentialURL))
        let request = try #require(JSONSerialization.jsonObject(with: body) as? [String: Any])
        #expect(request["credential_identifier"] as? String == "dataset-1")
        #expect(request["credential_configuration_id"] == nil)
    }

    @Test func HAIPAuthorizationCodeOfferPreviewsWithTrustPolicy() async throws {
        setup()
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            walletAttestationProvider: AuthorizationTestProvider(),
            issuerCertificateTrustSource: AuthorizationPreviewTrust())
        let preview = try await client.preview(offer: offerLink(scheme: "haip-vci"))
        #expect(preview.authorizationRequired)
        #expect(preview.credentialConfigurationId == "admin")
        #expect(StubURLProtocol.requests(to: parURL).isEmpty)
    }

    @Test func HAIPAuthorizationCodeRequiresScopeEvenWhenAuthorizationDetailsAreSupported() async throws {
        setup(supportsAuthorizationDetails: true)
        var metadata = TestIssuer.issuerMetadata()
        var configurations = metadata["credential_configurations_supported"] as! [String: Any]
        var admin = configurations["admin"] as! [String: Any]
        admin.removeValue(forKey: "scope")
        configurations["admin"] = admin
        metadata["credential_configurations_supported"] = configurations
        StubURLProtocol.on("GET", TestIssuer.base + "/.well-known/openid-credential-issuer", json: metadata)
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            walletAttestationProvider: AuthorizationTestProvider(),
            issuerCertificateTrustSource: AuthorizationPreviewTrust())
        await #expect(throws: WalletError.invalidIssuer("Each HAIP credential needs an OAuth scope.")) {
            try await client.preview(offer: offerLink(scheme: "haip-vci"))
        }
        #expect(StubURLProtocol.requests(to: parURL).isEmpty)
    }

    @Test func HAIPAuthorizationCodeRejectsBearerToken() async throws {
        setup()
        StubURLProtocol.on("POST", tokenURL, json: ["access_token": "AT", "token_type": "Bearer"])
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            walletAttestationProvider: AuthorizationTestProvider(),
            issuerCertificateTrustSource: AuthorizationPreviewTrust(),
            authorizationBrowser: approvingBrowser())
        let preview = try await client.preview(offer: offerLink(scheme: "haip-vci"))
        await #expect(throws: WalletError.offerConsumed(
            "The HAIP authorization server returned an unbound access token.")) {
            try await client.issue(preview, transactionCode: nil)
        }
        #expect(StubURLProtocol.requests(to: TestIssuer.base + "/vci/credential").isEmpty)
    }

    @Test func previewsDelegatedPathfulAuthorizationServer() async throws {
        setup()
        let serverID = "https://authorization.example.com/tenant-1"
        var issuerMetadata = TestIssuer.issuerMetadata()
        issuerMetadata["authorization_servers"] = [serverID]
        StubURLProtocol.on("GET", TestIssuer.base + "/.well-known/openid-credential-issuer", json: issuerMetadata)
        let serverMetadata: [String: Any] = [
            "issuer": serverID,
            "grant_types_supported": ["authorization_code"],
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": true,
            "dpop_signing_alg_values_supported": ["ES256"],
            "token_endpoint_auth_methods_supported": ["attest_jwt_client_auth"],
            "authorization_endpoint": serverID + "/authorization",
            "pushed_authorization_request_endpoint": serverID + "/pushed_authorization",
            "token_endpoint": serverID + "/token",
        ]
        StubURLProtocol.on(
            "GET", "https://authorization.example.com/.well-known/oauth-authorization-server/tenant-1",
            json: serverMetadata)
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            walletAttestationProvider: AuthorizationTestProvider())
        let preview = try await client.preview(offer: offerLink())
        #expect(preview.authorizationRequired)
        #expect(preview.authorizationServer.absoluteString == serverID)
        #expect(StubURLProtocol.requests(to: serverID + "/pushed_authorization").isEmpty)
    }

    @Test func offerHintSelectsOneOfMultipleAuthorizationServers() async throws {
        setup()
        let selectedServer = "https://authorization.example.com/tenant-1"
        var issuerMetadata = TestIssuer.issuerMetadata()
        issuerMetadata["authorization_servers"] = [TestIssuer.base + "/vci", selectedServer]
        StubURLProtocol.on("GET", TestIssuer.base + "/.well-known/openid-credential-issuer", json: issuerMetadata)
        var serverMetadata = TestIssuer.serverMetadata(
            issuer: selectedServer, tokenEndpoint: selectedServer + "/token")
        serverMetadata["grant_types_supported"] = ["authorization_code"]
        serverMetadata["response_types_supported"] = ["code"]
        serverMetadata["code_challenge_methods_supported"] = ["S256"]
        serverMetadata["authorization_response_iss_parameter_supported"] = true
        serverMetadata["dpop_signing_alg_values_supported"] = ["ES256"]
        serverMetadata["token_endpoint_auth_methods_supported"] = ["attest_jwt_client_auth"]
        serverMetadata["authorization_endpoint"] = selectedServer + "/authorize"
        serverMetadata["pushed_authorization_request_endpoint"] = selectedServer + "/par"
        let metadataURL = "https://authorization.example.com/.well-known/oauth-authorization-server/tenant-1"
        StubURLProtocol.on("GET", metadataURL, json: serverMetadata)
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            walletAttestationProvider: AuthorizationTestProvider())
        await #expect(throws: WalletError.self) { try await client.preview(offer: offerLink()) }
        let preview = try await client.preview(offer: offerLink(authorizationServer: selectedServer))
        #expect(preview.authorizationServer.absoluteString == selectedServer)
        #expect(StubURLProtocol.requests(to: metadataURL).count == 1)
    }

    @Test func rejectedPARDoesNotOpenBrowserOrSpendCode() async throws {
        setup(parStatus: 400, parBody: ["error": "invalid_request"])
        let opened = Box(false)
        let browser = AuthorizationTestBrowser { _ in
            opened.value = true
            throw WalletError.invalidIssuer("Browser should not open")
        }
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            walletAttestationProvider: AuthorizationTestProvider(), authorizationBrowser: browser)
        let preview = try await client.preview(offer: offerLink())
        await #expect(throws: WalletError.self) { try await client.issue(preview, transactionCode: nil) }
        #expect(!opened.value)
        #expect(StubURLProtocol.requests(to: tokenURL).isEmpty)
    }

    @Test func lostPARResponseLeavesOfferRetryable() async throws {
        setup()
        let parURL = parURL
        StubURLProtocol.on("POST", parURL) { _ in
            if StubURLProtocol.requests(to: parURL).count == 1 {
                return .init(failWith: .timedOut)
            }
            return .init(status: 400, headers: ["Content-Type": "application/json"],
                         body: Data(#"{"error":"invalid_request"}"#.utf8))
        }
        let browser = AuthorizationTestBrowser { _ in
            throw WalletError.invalidIssuer("Browser should not open")
        }
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            walletAttestationProvider: AuthorizationTestProvider(), authorizationBrowser: browser)
        let preview = try await client.preview(offer: offerLink())
        for _ in 0..<2 {
            do {
                _ = try await client.issue(preview, transactionCode: nil)
                Issue.record("PAR should have failed")
            } catch WalletError.network(_) {
                // A lost PAR response and a definite PAR rejection both leave this offer retryable.
            } catch {
                Issue.record("Expected a retryable network error, got \(error)")
            }
        }
        #expect(StubURLProtocol.requests(to: parURL).count == 2)
        #expect(StubURLProtocol.requests(to: tokenURL).isEmpty)
    }

    @Test func PARProofsRefreshForAttestationAndDPoPChallenges() async throws {
        setup()
        let parURL = parURL
        StubURLProtocol.on("POST", parURL) { _ in
            switch StubURLProtocol.requests(to: parURL).count {
            case 1:
                return .init(status: 400,
                             headers: ["Content-Type": "application/json",
                                       "OAuth-Client-Attestation-Challenge": "attestation-nonce"],
                             body: Data(#"{"error":"use_attestation_challenge"}"#.utf8))
            case 2:
                return .init(status: 400,
                             headers: ["Content-Type": "application/json", "DPoP-Nonce": "dpop-nonce"],
                             body: Data(#"{"error":"use_dpop_nonce"}"#.utf8))
            default:
                return .init(status: 201, headers: ["Content-Type": "application/json"],
                             body: Data(#"{"request_uri":"urn:example:request:2","expires_in":90}"#.utf8))
            }
        }
        let browser = AuthorizationTestBrowser { _ in throw WalletError.authorizationDenied }
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            walletAttestationProvider: AuthorizationTestProvider(), authorizationBrowser: browser)
        let preview = try await client.preview(offer: offerLink())
        await #expect(throws: WalletError.authorizationDenied) {
            try await client.issue(preview, transactionCode: nil)
        }
        let requests = StubURLProtocol.requests(to: parURL)
        #expect(requests.count == 3)
        for (index, request) in requests.enumerated() {
            let popText = try #require(request.value(forHTTPHeaderField: "OAuth-Client-Attestation-PoP"))
            let dpopText = try #require(request.value(forHTTPHeaderField: "DPoP"))
            let pop = try #require(JWS.parse(popText))
            let dpop = try #require(JWS.parse(dpopText))
            #expect(pop.payload["challenge"] as? String == (index == 0 ? nil : "attestation-nonce"))
            #expect(dpop.payload["nonce"] as? String == (index == 2 ? "dpop-nonce" : nil))
        }
        #expect(StubURLProtocol.requests(to: tokenURL).isEmpty)
    }

    @Test func selectedCredentialsDeterminePARScope() async throws {
        setup()
        var metadata = TestIssuer.issuerMetadata()
        var configurations = metadata["credential_configurations_supported"] as! [String: Any]
        var learning = configurations["admin"] as! [String: Any]
        learning["scope"] = "learning"
        configurations["learning"] = learning
        metadata["credential_configurations_supported"] = configurations
        StubURLProtocol.on("GET", TestIssuer.base + "/.well-known/openid-credential-issuer", json: metadata)
        let offer: [String: Any] = [
            "credential_issuer": TestIssuer.base,
            "credential_configuration_ids": ["admin", "learning"],
            "grants": ["authorization_code": ["issuer_state": "ISSUER-STATE"]],
        ]
        let link = "openid-credential-offer://?credential_offer=" +
            String(decoding: try JSONSerialization.data(withJSONObject: offer), as: UTF8.self)
                .addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        let browser = AuthorizationTestBrowser { _ in throw WalletError.authorizationDenied }
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            walletAttestationProvider: AuthorizationTestProvider(), authorizationBrowser: browser)
        let preview = try await client.preview(offer: link)
        #expect(preview.credentials.count == 2)
        await #expect(throws: WalletError.authorizationDenied) {
            try await client.issueAll(preview, selectedConfigurationIds: ["learning"], transactionCode: nil)
        }
        #expect(try form(parURL)["scope"] == "learning")
        #expect(StubURLProtocol.requests(to: tokenURL).isEmpty)
    }
}
}

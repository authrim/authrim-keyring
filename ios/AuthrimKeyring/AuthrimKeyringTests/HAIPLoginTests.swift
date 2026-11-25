import CryptoKit
import Foundation
import Testing
@testable import AuthrimKeyring

extension StubbedNetworkTests {
@Suite(.serialized)
struct HAIPLoginTests {
    static let host = "issuer.example.com"
    static let requestID = "g1:apac:3:vp_0f3a9c1e-5b7d-4e2a-8c6f-1a2b3c4d5e6f"
    static var requestURL: String { "https://\(host)/vp/login/request/" + requestID.addingPercentEncoding(withAllowedCharacters: .alphanumerics)! }
    static var responseURL: String { "https://\(host)/vp/login/response" }

    init() { StubURLProtocol.reset() }

    private let holder = TestSigner(tag: "com.authrim.keyring.vc.holder.login-test", key: P256.Signing.PrivateKey())
    private let verifierKey = P256.KeyAgreement.PrivateKey()
    private var leaf: Data { Data(base64Encoded: AuthrimPKIFixture.leaf)! }
    private var ca: Data { Data(base64Encoded: AuthrimPKIFixture.issuingCA)! }
    private var root: Data { Data(base64Encoded: AuthrimPKIFixture.root)! }
    private var leafKey: P256.Signing.PrivateKey {
        try! P256.Signing.PrivateKey(rawRepresentation: Data(base64Encoded: AuthrimPKIFixture.leafScalar)!)
    }
    private var clientID: String { "x509_hash:" + Base64URL.encode(Data(SHA256.hash(data: leaf))) }

    private func credential(vct: String = TestIssuer.vct, withTenant: Bool = true) throws -> StoredCredential {
        var options = TestIssuer.Options()
        options.signWith = leafKey
        options.vct = vct
        options.extraHeader = ["x5c": [AuthrimPKIFixture.leaf, AuthrimPKIFixture.issuingCA]]
        if withTenant { options.extraPayload = ["tenant_id": "default"] }
        let sd = try TestIssuer().sdJwt(holder: holder.publicJWK, options)
        return StoredCredential(
            id: UUID(), issuer: URL(string: "https://\(Self.host)")!, issuerDisplayName: nil,
            credentialConfigurationId: "admin", vct: vct, credentialName: "Admin", claims: [:],
            issuedAt: Date(), expiresAt: Date().addingTimeInterval(3_600), keyTag: holder.tag,
            confirmationCode: "ABCD-EFGH", sdJwt: sd)
    }

    private func dcql(extra: [String: Any] = [:], authority: [Data]? = nil) -> [String: Any] {
        var query: [String: Any] = [
            "id": "admin", "format": "dc+sd-jwt", "meta": ["vct_values": [TestIssuer.vct]],
            "claims": [["path": ["sub"]], ["path": ["tenant_id"]]],
        ]
        if let authority { query["trusted_authorities"] = [["type": "aki", "values": authority.map(Base64URL.encode)]] }
        query.merge(extra) { _, new in new }
        return ["credentials": [query]]
    }

    private func payload(_ changes: [String: Any] = [:]) -> [String: Any] {
        let now = Int(Date().timeIntervalSince1970)
        let key = PublicJWK(x963: verifierKey.publicKey.x963Representation)!
        var jwk = key.proofMembers
        jwk["kid"] = Self.requestID
        jwk["use"] = "enc"
        jwk["alg"] = "ECDH-ES"
        var object: [String: Any] = [
            "aud": "https://self-issued.me/v2", "client_id": clientID, "response_type": "vp_token",
            "response_mode": "direct_post.jwt", "response_uri": Self.responseURL,
            "nonce": "NONCE-0123456789abcdef", "state": "STATE-1", "iat": now, "exp": now + 300,
            "client_metadata": ["jwks": ["keys": [jwk]], "encrypted_response_enc_values_supported": ["A128GCM", "A256GCM"]],
            "dcql_query": dcql(),
        ]
        object.merge(changes) { _, new in new }
        return object
    }

    /// Serves a request object signed like the Authrim verifier's (leaf key, chain without the root).
    private func serve(
        _ changes: [String: Any] = [:], x5c: [String]? = nil, signer: P256.Signing.PrivateKey? = nil,
        redirect: String = "https://issuer.example.com/admin/login/wallet?request_id=r&response_code=c"
    ) throws {
        let key = signer ?? leafKey
        let jwt = try JWS.make(
            header: ["alg": "ES256", "typ": "oauth-authz-req+jwt",
                     "x5c": x5c ?? [AuthrimPKIFixture.leaf, AuthrimPKIFixture.issuingCA]],
            payload: payload(changes)) { try key.signature(for: $0).rawRepresentation }
        StubURLProtocol.on("GET", Self.requestURL) { _ in
            .init(headers: ["Content-Type": "application/oauth-authz-req+jwt"], body: Data(jwt.utf8))
        }
        StubURLProtocol.on("POST", Self.responseURL, json: ["redirect_uri": redirect])
    }

    private func link(_ id: String? = nil) -> String {
        "haip-vp://?client_id=\((id ?? clientID).addingPercentEncoding(withAllowedCharacters: .alphanumerics)!)&request_uri="
            + Self.requestURL.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
    }

    private func client(roots: [Data]? = nil, consoleHosts: Set<String> = [], adminVCTs: Set<String> = [TestIssuer.vct]) -> HAIPLoginClient {
        let holder = holder
        return HAIPLoginClient(
            roots: roots ?? [root], consoleHosts: consoleHosts, adminVCTs: adminVCTs,
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]),
            sign: { _, message, _ in try holder.sign(message) })
    }

    @Test func answersASignInRequestWithAnEncryptedPresentation() async throws {
        try serve()
        let stored = try credential()
        let c = client()
        let request = try await c.preview(link: link(), credentials: [stored])
        #expect(request.enc == "A256GCM" && request.verifierHost == Self.host && request.queryID == "admin")
        let url = try await c.present(request)
        #expect(url.absoluteString.hasPrefix("https://issuer.example.com/admin/login/wallet"))

        let body = try #require(StubURLProtocol.body(of: Self.responseURL))
        let items = URLComponents(string: "https://x.test/?" + String(decoding: body, as: UTF8.self))?.queryItems ?? []
        #expect(items.map(\.name) == ["response"])
        let jwe = try #require(items.first?.value)
        let opened = try WalletJWETests.decrypt(jwe, with: verifierKey)
        #expect(opened.header["kid"] as? String == Self.requestID)
        let object = try #require(JSONSerialization.jsonObject(with: opened.plaintext) as? [String: Any])
        #expect(object["state"] as? String == "STATE-1")
        let token = try #require(object["vp_token"] as? [String: Any])
        let presentation = try #require((token["admin"] as? [String])?.first)
        let pieces = presentation.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
        #expect(pieces.count == 2)
        let issuerJWT = try ParsedSDJWT(stored.sdJwt).issuerJWT
        #expect(pieces[0] == issuerJWT)
        let kb = try #require(JWS.parse(pieces[1]))
        #expect(kb.header["typ"] as? String == "kb+jwt")
        #expect(kb.payload["aud"] as? String == clientID)
        #expect(kb.payload["nonce"] as? String == "NONCE-0123456789abcdef")
        #expect(kb.payload["sd_hash"] as? String == OpenID4VPClient.sha256(issuerJWT + "~"))
        #expect(JWS.verifyES256(kb, with: holder.key.publicKey))
    }

    @Test func linkParsingIsStrict() throws {
        #expect(HAIPLoginLink.isLoginLink(link()))
        #expect(!HAIPLoginLink.isLoginLink("openid4vp://?client_id=decentralized_identifier%3Adid%3Aweb%3Aissuer.example.com&request_uri=x"))
        _ = try HAIPLoginLink(link())
        let other = Self.requestURL.replacingOccurrences(of: "/login/request/", with: "/admin/request/")
        for text in [
            link() + "&extra=1",
            link().replacingOccurrences(of: "haip-vp", with: "https"),
            "haip-vp://?client_id=x509_hash%3Ashort&request_uri=" + Self.requestURL,
            "haip-vp://?client_id=\(clientID)&request_uri=" + other.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!,
            "haip-vp://?client_id=\(clientID)&request_uri=" + "http://issuer.example.com/vp/login/request/x",
        ] {
            #expect(throws: WalletError.self, Comment(rawValue: text)) { _ = try HAIPLoginLink(text) }
        }
    }

    @Test func refusesRequestsThatAreNotFromTheAuthrimVerifier() async throws {
        let stored = try credential()
        let otherRoot = try #require(Data(base64Encoded: IssuerX509VerifierTests.root))
        let other = P256.Signing.PrivateKey()
        let cases: [(String, () async throws -> Void)] = [
            ("untrusted root", { try self.serve(); _ = try await self.client(roots: [otherRoot]).preview(link: self.link(), credentials: [stored]) }),
            ("root in chain", { try self.serve(x5c: [AuthrimPKIFixture.leaf, AuthrimPKIFixture.issuingCA, AuthrimPKIFixture.root]); _ = try await self.client().preview(link: self.link(), credentials: [stored]) }),
            ("leaf only", { try self.serve(x5c: [AuthrimPKIFixture.leaf]); _ = try await self.client().preview(link: self.link(), credentials: [stored]) }),
            ("signed by another key", { try self.serve(signer: other); _ = try await self.client().preview(link: self.link(), credentials: [stored]) }),
            ("hash of another cert", { try self.serve(); _ = try await self.client().preview(link: self.link("x509_hash:" + Base64URL.encode(Data(SHA256.hash(data: self.ca)))), credentials: [stored]) }),
            ("payload client id differs", { try self.serve(["client_id": "x509_hash:AAAA"]); _ = try await self.client().preview(link: self.link(), credentials: [stored]) }),
        ]
        for (name, run) in cases {
            StubURLProtocol.reset()
            await #expect(throws: WalletError.self, Comment(rawValue: name)) { try await run() }
        }
    }

    @Test func refusesUnsupportedOrUnsafeRequestContent() async throws {
        let stored = try credential()
        let key = PublicJWK(x963: verifierKey.publicKey.x963Representation)!.proofMembers
        let cases: [(String, [String: Any])] = [
            ("transaction data", ["transaction_data": ["x"]]),
            ("another host", ["response_uri": "https://evil.example.com/vp/login/response"]),
            ("plain direct_post", ["response_mode": "direct_post"]),
            ("expired", ["exp": Int(Date().timeIntervalSince1970) - 10]),
            ("no supported enc", ["client_metadata": ["jwks": ["keys": [key]], "encrypted_response_enc_values_supported": ["A192GCM"]]]),
            ("two keys", ["client_metadata": ["jwks": ["keys": [key, key]], "encrypted_response_enc_values_supported": ["A128GCM"]]]),
            ("more claims", ["dcql_query": dcql(extra: ["claims": [["path": ["email"]]]])]),
            ("claim values", ["dcql_query": dcql(extra: ["claims": [["path": ["sub"], "values": ["x"]]]])]),
            ("other authority type", ["dcql_query": dcql(extra: ["trusted_authorities": [["type": "etsi_tl", "values": ["x"]]]])]),
            ("no kid", ["client_metadata": ["jwks": ["keys": [key]], "encrypted_response_enc_values_supported": ["A128GCM"]]]),
            ("key alg for another JWE algorithm", ["client_metadata": ["jwks": ["keys": [key.merging(["kid": "k", "alg": "ECDH-ES+A256KW"]) { _, n in n }]], "encrypted_response_enc_values_supported": ["A128GCM"]]]),
            ("no matching vct", ["dcql_query": dcql(extra: ["meta": ["vct_values": ["urn:other"]]])]),
        ]
        for (name, changes) in cases {
            StubURLProtocol.reset()
            try serve(changes)
            await #expect(throws: WalletError.self, Comment(rawValue: name)) {
                _ = try await self.client().preview(link: self.link(), credentials: [stored])
            }
        }
    }

    @Test func authorityKeyIdentifierMatchesTheCredentialsChain() async throws {
        let stored = try credential()
        let leafAKI = try #require(CertificateKeyIdentifiers.authorityKeyIdentifier(of: leaf))
        try serve(["dcql_query": dcql(authority: [Data(repeating: 1, count: 20), leafAKI])])
        _ = try await client().preview(link: link(), credentials: [stored])
        StubURLProtocol.reset()
        try serve(["dcql_query": dcql(authority: [Data(repeating: 1, count: 20)])])
        await #expect(throws: WalletError.noMatchingCredential) {
            _ = try await self.client().preview(link: self.link(), credentials: [stored])
        }
    }

    @Test func answersOnlyWithAdminCredentialsThatCarryTheRequestedClaims() async throws {
        try serve()
        let noTenant = try credential(withTenant: false)
        await #expect(throws: WalletError.noMatchingCredential) {
            _ = try await self.client().preview(link: self.link(), credentials: [noTenant])
        }
        let ordinary = try credential(vct: "https://issuer.example.com/vct/other")
        StubURLProtocol.reset()
        try serve(["dcql_query": dcql(extra: ["meta": ["vct_values": ["https://issuer.example.com/vct/other"]]])])
        await #expect(throws: WalletError.self) {
            _ = try await self.client().preview(link: self.link(), credentials: [ordinary])
        }
        #expect(StubURLProtocol.requests(to: Self.requestURL).isEmpty)
    }

    @Test func fetchesNothingFromAHostThatIssuedNoCredential() async throws {
        try serve()
        let elsewhere = StoredCredential(
            id: UUID(), issuer: URL(string: "https://other.example.com")!, issuerDisplayName: nil,
            credentialConfigurationId: "admin", vct: TestIssuer.vct, credentialName: "Admin", claims: [:],
            issuedAt: Date(), expiresAt: nil, keyTag: "t", confirmationCode: "X", sdJwt: "a.b.c~")
        await #expect(throws: WalletError.self) {
            _ = try await self.client().preview(link: self.link(), credentials: [elsewhere])
        }
        #expect(StubURLProtocol.requests(to: Self.requestURL).isEmpty)
    }

    @Test func opensOnlyTheVerifierOrAConfiguredConsoleHost() async throws {
        let stored = try credential()
        try serve(redirect: "https://admin.example.net/admin/login/wallet?request_id=r&response_code=c")
        let request = try await client().preview(link: link(), credentials: [stored])
        await #expect(throws: WalletError.self) { _ = try await self.client().present(request) }
        _ = try await client(consoleHosts: ["admin.example.net"]).present(request)
        for bad in ["http://issuer.example.com/x", "https://evil.example.com/x", "https://issuer.example.com/x#f", "https://issuer.example.com:8443/x"] {
            StubURLProtocol.reset()
            try serve(redirect: bad)
            let r = try await client().preview(link: link(), credentials: [stored])
            await #expect(throws: WalletError.self, Comment(rawValue: bad)) { _ = try await self.client(consoleHosts: ["admin.example.net"]).present(r) }
        }
    }
}
}

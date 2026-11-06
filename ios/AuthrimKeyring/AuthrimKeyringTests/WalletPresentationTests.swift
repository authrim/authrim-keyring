import CryptoKit
import Foundation
import Testing
@testable import AuthrimKeyring

/// Administrator presentations (OpenID4VP): the checks of the request and the answer sent, with the
/// network stubbed and real signatures. Serialized: the stub registry is shared.
extension StubbedNetworkTests {
@Suite(.serialized)
struct WalletPresentationTests {
    static let host = "issuer.example.com"
    static let did = "did:web:issuer.example.com"
    static let clientID = "decentralized_identifier:did:web:issuer.example.com"
    static let requestURL = "https://issuer.example.com/vp/admin/request/g1%3Aapac%3A0%3Avp_0f8c2d4e-1b3a-4c5d-9e7f-123456789abc"
    static let responseURL = "https://issuer.example.com/vp/admin/response"
    static let vct = "https://authrim.com/credentials/admin/v1"
    static let issuerJWT = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhZG1pbi0xIn0.c2ln"

    let verifierKey = P256.Signing.PrivateKey()
    let holderKey = P256.Signing.PrivateKey()
    let now = Date(timeIntervalSince1970: 1_800_000_000)

    init() { StubURLProtocol.reset() }

    static var link: String {
        let allowed = CharacterSet.alphanumerics
        return "openid4vp://?client_id=\(clientID.addingPercentEncoding(withAllowedCharacters: allowed)!)"
            + "&request_uri=\(requestURL.addingPercentEncoding(withAllowedCharacters: allowed)!)"
    }

    var credential: StoredCredential {
        StoredCredential(
            id: UUID(), issuer: URL(string: "https://\(Self.host)")!, issuerDisplayName: nil,
            credentialConfigurationId: "AuthrimAdminCredential", vct: Self.vct, credentialName: "Authrim Admin",
            claims: [:], issuedAt: now.addingTimeInterval(-3600), expiresAt: now.addingTimeInterval(86_400),
            keyTag: "com.authrim.keyring.vc.holder.test", confirmationCode: "ABCD-EFGH",
            sdJwt: Self.issuerJWT + "~WyJzIiwiZW1haWwiLCJhQGIuYyJd~")
    }

    var transactionData: String {
        let json = #"{"type":"authrim_admin_step_up","credential_ids":["admin"],"purpose":"step_up","tenant":"issuer.example.com"}"#
        return Base64URL.encode(Data(json.utf8))
    }

    func payload(_ change: (inout [String: Any]) -> Void = { _ in }) -> [String: Any] {
        var value: [String: Any] = [
            "aud": "https://self-issued.me/v2",
            "client_id": Self.clientID,
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "response_uri": Self.responseURL,
            "nonce": "nonce-0123456789abcdef",
            "state": "req-1",
            "iat": now.timeIntervalSince1970,
            "exp": now.timeIntervalSince1970 + 300,
            "dcql_query": ["credentials": [[
                "id": "admin", "format": "dc+sd-jwt", "meta": ["vct_values": [Self.vct]],
                "claims": [["path": ["sub"]], ["path": ["tenant_id"]]],
            ]]],
            "transaction_data": [transactionData],
        ]
        change(&value)
        return value
    }

    func requestObject(
        _ payload: [String: Any], key: P256.Signing.PrivateKey? = nil, kid: String = "did:web:issuer.example.com#k1",
        typ: String = "oauth-authz-req+jwt", extraHeader: [String: Any] = [:]
    ) throws -> String {
        let signer = key ?? verifierKey
        let header = ["alg": "ES256", "typ": typ, "kid": kid].merging(extraHeader) { $1 }
        return try JWS.make(header: header, payload: payload) {
            try signer.signature(for: $0).rawRepresentation
        }
    }

    func didDocument(key: P256.Signing.PrivateKey? = nil, inAssertion: Bool = true) -> [String: Any] {
        let jwk = PublicJWK(x963: (key ?? verifierKey).publicKey.x963Representation)!
        let method: [String: Any] = [
            "id": "#k1", "type": "JsonWebKey2020", "controller": Self.did,
            "publicKeyJwk": ["kty": "EC", "crv": "P-256", "x": jwk.x, "y": jwk.y],
        ]
        return ["id": Self.did, "verificationMethod": [method], "assertionMethod": inAssertion ? ["#k1"] : []]
    }

    func stub(requestObject jwt: String, document: [String: Any]? = nil) {
        StubURLProtocol.on("GET", Self.requestURL) { _ in
            .init(headers: ["Content-Type": "application/oauth-authz-req+jwt"], body: Data(jwt.utf8))
        }
        StubURLProtocol.on("GET", "https://\(Self.host)/.well-known/did.json", json: document ?? didDocument())
    }

    func client() -> OpenID4VPClient {
        let holder = holderKey
        let now = now
        return OpenID4VPClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), now: { now },
            sign: { _, message, _ in try holder.signature(for: message).rawRepresentation })
    }

    // MARK: Request checks

    @Test func acceptsASignedRequestFromTheIssuerOfACredential() async throws {
        stub(requestObject: try requestObject(payload()))
        let request = try await client().preview(link: Self.link, credentials: [credential])
        #expect(request.verifierHost == Self.host)
        #expect(request.purpose == .stepUp)
        #expect(request.state == "req-1")
        #expect(request.credential.vct == Self.vct)
    }

    @Test(arguments: [
        (#"{"type":"authrim_admin_step_up","credential_ids":["admin"],"purpose":"enroll","mode":"recovery"}"#, true),
        (#"{"type":"authrim_admin_step_up","credential_ids":["admin"],"purpose":"enroll"}"#, false),
        // Only a registration can be a recovery request.
        (#"{"type":"authrim_admin_step_up","credential_ids":["admin"],"purpose":"step_up","mode":"recovery"}"#, false),
    ])
    func readsWhetherARegistrationFilesARecoveryRequest(_ json: String, isRecovery: Bool) async throws {
        let data = Base64URL.encode(Data(json.utf8))
        stub(requestObject: try requestObject(payload { $0["transaction_data"] = [data] }))
        let request = try await client().preview(link: Self.link, credentials: [credential])
        #expect(request.isRecovery == isRecovery)
    }

    @Test func fetchesNothingFromAServerThatIssuedNoCredentialHere() async throws {
        await #expect(throws: WalletError.self) {
            _ = try await client().preview(link: Self.link, credentials: [])
        }
        #expect(StubURLProtocol.requests(to: Self.requestURL).isEmpty)
    }

    @Test func refusesASignatureByAKeyTheDIDDoesNotPublish() async throws {
        stub(requestObject: try requestObject(payload(), key: P256.Signing.PrivateKey()))
        await expectUntrusted { try await client().preview(link: Self.link, credentials: [credential]) }
    }

    @Test func refusesAKeyThatIsNotAnAssertionMethod() async throws {
        stub(requestObject: try requestObject(payload()), document: didDocument(inAssertion: false))
        await expectUntrusted { try await client().preview(link: Self.link, credentials: [credential]) }
    }

    @Test func refusesAKeyOfAnotherDID() async throws {
        stub(requestObject: try requestObject(payload(), kid: "did:web:evil.example#k1"))
        await expectUntrusted { try await client().preview(link: Self.link, credentials: [credential]) }
    }

    @Test func refusesAnUnsignedOrOtherwiseTypedRequest() async throws {
        stub(requestObject: try requestObject(payload(), typ: "JWT"))
        await expectUntrusted { try await client().preview(link: Self.link, credentials: [credential]) }
    }

    @Test(arguments: [
        "https://evil.example/vp/admin/response",
        "http://issuer.example.com/vp/admin/response",
        "https://issuer.example.com:8443/vp/admin/response",
    ])
    func refusesAnAnswerToAnotherPlace(responseURI: String) async throws {
        stub(requestObject: try requestObject(payload { $0["response_uri"] = responseURI }))
        await expectUntrusted { try await client().preview(link: Self.link, credentials: [credential]) }
    }

    @Test func refusesARequestForMoreThanTheAdminCredential() async throws {
        let wider = payload {
            $0["dcql_query"] = ["credentials": [[
                "id": "admin", "format": "dc+sd-jwt", "meta": ["vct_values": [Self.vct]],
                "claims": [["path": ["email"]]],
            ]]]
        }
        stub(requestObject: try requestObject(wider))
        await #expect(throws: WalletError.invalidRequest("The request asks for more than the admin credential needs.")) {
            _ = try await client().preview(link: Self.link, credentials: [credential])
        }
    }

    @Test func refusesConditionsItDoesNotApply() async throws {
        let withValues = payload {
            $0["dcql_query"] = ["credentials": [[
                "id": "admin", "format": "dc+sd-jwt", "meta": ["vct_values": [Self.vct]],
                "claims": [["path": ["sub"], "values": ["admin-2"]]],
            ]]]
        }
        stub(requestObject: try requestObject(withValues))
        await #expect(throws: WalletError.invalidRequest("The request has conditions Keyring does not support.")) {
            _ = try await client().preview(link: Self.link, credentials: [credential])
        }
        let withClaimSets = payload {
            $0["dcql_query"] = ["credentials": [[
                "id": "admin", "format": "dc+sd-jwt", "meta": ["vct_values": [Self.vct]],
                "claim_sets": [["a"]],
            ]]]
        }
        stub(requestObject: try requestObject(withClaimSets))
        await #expect(throws: WalletError.invalidRequest("The request has conditions Keyring does not support.")) {
            _ = try await client().preview(link: Self.link, credentials: [credential])
        }
        let malformed = payload {
            $0["dcql_query"] = ["credentials": [[
                "id": "admin", "format": "dc+sd-jwt", "meta": ["vct_values": [Self.vct]],
                "claims": [["path": ["sub"], "values": ["admin-2"]], NSNull()] as [Any],
            ]]]
        }
        stub(requestObject: try requestObject(malformed))
        await #expect(throws: WalletError.invalidRequest("The request has conditions Keyring does not support.")) {
            _ = try await client().preview(link: Self.link, credentials: [credential])
        }
    }

    @Test func refusesAnExpiredRequest() async throws {
        stub(requestObject: try requestObject(payload {
            $0["iat"] = now.timeIntervalSince1970 - 900
            $0["exp"] = now.timeIntervalSince1970 - 600
        }))
        await #expect(throws: WalletError.invalidRequest("The request has expired.")) {
            _ = try await client().preview(link: Self.link, credentials: [credential])
        }
    }

    @Test func refusesARequestWithoutItsPurpose() async throws {
        stub(requestObject: try requestObject(payload { $0["transaction_data"] = [] as [String] }))
        await #expect(throws: WalletError.invalidRequest("The request does not say what it is for.")) {
            _ = try await client().preview(link: Self.link, credentials: [credential])
        }
    }

    @Test(arguments: [
        "openid4vp://?request=eyJ",
        "openid4vp://?client_id=x",
        "openid4vp://?client_id=x&request_uri=http%3A%2F%2Fissuer.example.com%2Fr",
        "openid4vp://?client_id=x&request_uri=https%3A%2F%2Fissuer.example.com%2Fr&request_uri_method=post",
        "https://issuer.example.com/r",
        "openid4vp://?client_id=x&request_uri=https%3A%2F%2Fissuer.example.com%2Fadmin%2Fdelete",
        "openid4vp://?client_id=x&request_uri=https%3A%2F%2Fissuer.example.com%2Fvp%2Fadmin%2Frequest%2Fa%3Ftoken%3D1",
        "openid4vp://?client_id=x&request_uri=https%3A%2F%2Fissuer.example.com%2Fvp%2Fadmin%2Frequest%2Fa%2Fb",
        "openid4vp://?client_id=x&request_uri=https%3A%2F%2Fissuer.example.com%2Fvp%2Fadmin%2Frequest%2F",
        "openid4vp://?client_id=x&request_uri=https%3A%2F%2Fissuer.example.com%2Fvp%2Fadmin%2Frequest%2F..",
        "openid4vp://?client_id=x&request_uri=https%3A%2F%2Fissuer.example.com%2Fvp%2Fadmin%2Frequest%2F%252e%252e",
        "openid4vp://?client_id=x&request_uri=https%3A%2F%2Fissuer.example.com%2Fvp%2Fadmin%2Frequest%2Freq-1",
        "openid4vp://?client_id=x&request_uri=https%3A%2F%2Fissuer.example.com%2Fvp%2Fadmin%2Frequest%2Fg1%253Aapac%253A0%253Avp_--------",
        "openid4vp://?client_id=x&request_uri=https%3A%2F%2Fissuer.example.com%2Fvp%2Fadmin%2Frequest%2Fg1%253Aapac%253A0%253Avp_12345678",
        "openid4vp://?client_id=x&request_uri=https%3A%2F%2Fissuer.example.com%2Fvp%2Fadmin%2Frequest%2Fg1%253Aapac%253A0%253Avp_0f8c2d4e1b3a4c5d9e7f123456789abc",
    ])
    func refusesLinksThatAreNotSignedRequestsByReference(link: String) {
        #expect(throws: WalletError.notAPresentationRequest) { _ = try PresentationLink(link) }
    }

    @Test func sendsNothingToAnotherPortOfTheIssuerHost() async throws {
        let allowed = CharacterSet.alphanumerics
        let link = "openid4vp://?client_id=\(Self.clientID.addingPercentEncoding(withAllowedCharacters: allowed)!)"
            + "&request_uri=\("https://issuer.example.com:8443/r".addingPercentEncoding(withAllowedCharacters: allowed)!)"
        await #expect(throws: WalletError.self) {
            _ = try await client().preview(link: link, credentials: [credential])
        }
        #expect(StubURLProtocol.requests(to: "https://issuer.example.com:8443/r").isEmpty)
    }

    @Test func refusesARequestForAnotherAudience() async throws {
        stub(requestObject: try requestObject(payload { $0["aud"] = "https://verifier.example/wallet" }))
        await #expect(throws: WalletError.invalidRequest("The request is addressed to another wallet.")) {
            _ = try await client().preview(link: Self.link, credentials: [credential])
        }
        stub(requestObject: try requestObject(payload { $0.removeValue(forKey: "aud") }))
        await #expect(throws: WalletError.invalidRequest("The request is addressed to another wallet.")) {
            _ = try await client().preview(link: Self.link, credentials: [credential])
        }
    }

    @Test func refusesACriticalHeaderExtension() async throws {
        stub(requestObject: try requestObject(payload(), extraHeader: ["crit": ["x"], "x": true]))
        await expectUntrusted { try await client().preview(link: Self.link, credentials: [credential]) }
    }

    @Test func sendsNothingWhenTheRequestExpiredDuringFaceID() async throws {
        stub(requestObject: try requestObject(payload()))
        let clock = Box(now)
        let holder = holderKey
        let client = OpenID4VPClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), now: { clock.value },
            sign: { _, message, _ in
                // The admin takes six minutes to confirm.
                clock.value = clock.value.addingTimeInterval(360)
                return try holder.signature(for: message).rawRepresentation
            })
        let request = try await client.preview(link: Self.link, credentials: [credential])
        StubURLProtocol.on("POST", Self.responseURL, json: [:])
        await #expect(throws: WalletError.invalidRequest("The request has expired.")) {
            try await client.present(request, matchCode: "42")
        }
        #expect(StubURLProtocol.requests(to: Self.responseURL).isEmpty)
    }

    // MARK: The answer

    @Test func sendsTheCredentialWithoutDisclosuresAndAKeyBindingOverEverything() async throws {
        stub(requestObject: try requestObject(payload()))
        let client = client()
        let request = try await client.preview(link: Self.link, credentials: [credential])
        StubURLProtocol.on("POST", Self.responseURL, json: [:])
        try await client.present(request, matchCode: "42")

        let body = try #require(StubURLProtocol.body(of: Self.responseURL))
        let form = Dictionary(
            uniqueKeysWithValues: (URLComponents(string: "?" + String(decoding: body, as: UTF8.self))?.queryItems ?? [])
                .map { ($0.name, $0.value ?? "") })
        #expect(form["state"] == "req-1")
        let token = try #require(
            (try JSONSerialization.jsonObject(with: Data(form["vp_token"]!.utf8))) as? [String: [String]])
        let presentation = try #require(token["admin"]?.first)
        #expect(token.keys.sorted() == ["admin"])

        // `<issuer JWT>~<KB-JWT>`: the stored disclosure (email) is not sent.
        let pieces = presentation.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
        #expect(pieces.count == 2)
        #expect(pieces[0] == Self.issuerJWT)
        let kb = try #require(JWS.parse(pieces[1]))
        #expect(kb.header["typ"] as? String == "kb+jwt")
        #expect(JWS.verifyES256(kb, with: holderKey.publicKey))
        #expect(kb.payload["aud"] as? String == Self.clientID)
        #expect(kb.payload["nonce"] as? String == "nonce-0123456789abcdef")
        #expect(kb.payload["sd_hash"] as? String == OpenID4VPClient.sha256(Self.issuerJWT + "~"))
        #expect(kb.payload["transaction_data_hashes"] as? [String] == [OpenID4VPClient.sha256(transactionData)])
        #expect(kb.payload["authrim_match_code"] as? String == "42")
    }

    @Test func reportsARefusedAnswer() async throws {
        stub(requestObject: try requestObject(payload()))
        let client = client()
        let request = try await client.preview(link: Self.link, credentials: [credential])
        StubURLProtocol.on(
            "POST", Self.responseURL, json: ["error": "access_denied", "error_description": "match_code_mismatch"],
            status: 400)
        await #expect(throws: WalletError.presentationRefused("match_code_mismatch")) {
            try await client.present(request, matchCode: "41")
        }
    }

    @Test(arguments: ["", "4", "421", "4a"])
    func asksForExactlyTwoDigits(code: String) async throws {
        stub(requestObject: try requestObject(payload()))
        let client = client()
        let request = try await client.preview(link: Self.link, credentials: [credential])
        await #expect(throws: WalletError.self) { try await client.present(request, matchCode: code) }
        #expect(StubURLProtocol.requests(to: Self.responseURL).isEmpty)
    }

    private func expectUntrusted(_ body: () async throws -> PresentationRequest) async {
        do {
            _ = try await body()
            Issue.record("The request was accepted")
        } catch let error as WalletError {
            guard case .untrustedVerifier = error else {
                Issue.record("Unexpected error \(error)")
                return
            }
        } catch {
            Issue.record("Unexpected error \(error)")
        }
    }
}
}

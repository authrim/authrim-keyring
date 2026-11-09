import CryptoKit
import Foundation
import Testing
@testable import AuthrimKeyring

/// A test stand-in for a provider that has already verified and trusted its own attestation.
/// The production provider verifies its certificate chain before returning this type.
private struct MockWalletAttestationProvider: WalletAttestationProvider {
    let receivedClientKey: Box<PublicJWK?>
    let signingKey = P256.Signing.PrivateKey()

    func supports(issuer: URL) -> Bool { issuer.absoluteString == TestIssuer.base }

    func attestation(for clientKey: PublicJWK, issuer: URL) async throws -> WalletClientAttestation {
        receivedClientKey.value = clientKey
        let jwt = try JWS.make(
            header: ["typ": "oauth-client-attestation+jwt", "alg": "ES256", "x5c": ["mock-certificate"]],
            payload: [
                "iss": "https://wallet-provider.example.com", "sub": "wallet.example",
                "iat": 1_700_000_000, "nbf": 1_700_000_000, "exp": 2_000_000_000,
                "cnf": ["jwk": clientKey.proofMembers],
            ]) { message in
                try signingKey.signature(for: message).rawRepresentation
            }
        return WalletClientAttestation(jwt: jwt, clientID: "wallet.example")
    }
}

private actor FlakyWalletAttestationProvider: WalletAttestationProvider {
    private var attempts = 0

    nonisolated func supports(issuer: URL) -> Bool { issuer.absoluteString == TestIssuer.base }

    func attestation(for clientKey: PublicJWK, issuer: URL) async throws -> WalletClientAttestation {
        attempts += 1
        if attempts == 1 { throw WalletError.outcomeUnknown("Temporary provider timeout.") }
        return WalletClientAttestation(jwt: "test-attestation", clientID: "wallet.example")
    }
}

private actor TokenRequestCounter {
    private var requests = 0

    func record() { requests += 1 }
    func count() -> Int { requests }
}

extension StubbedNetworkTests {
@Suite(.serialized)
struct WalletAttestationTokenTests {
    init() { StubURLProtocol.reset() }

    @Test func providerTimeoutBeforeTokenLeavesOfferRetryable() async throws {
        let base = TestIssuer.base
        let offer = TestIssuer.offerJSON(txCode: false)
        let encoded = try #require(String(decoding: JSONSerialization.data(withJSONObject: offer), as: UTF8.self)
            .addingPercentEncoding(withAllowedCharacters: .alphanumerics))
        let link = "openid-credential-offer://?credential_offer=\(encoded)"
        var server = TestIssuer.serverMetadata()
        server["dpop_signing_alg_values_supported"] = ["ES256"]
        server["token_endpoint_auth_methods_supported"] = ["attest_jwt_client_auth"]
        func response(_ json: Any, status: Int = 200) throws -> WalletHTTPResponse {
            WalletHTTPResponse(
                status: status, data: try JSONSerialization.data(withJSONObject: json),
                dpopNonce: nil, wwwAuthenticate: nil, clientAttestationChallenge: nil)
        }
        let tokenURL = base + "/vci/token"
        let replies = [
            "GET \(base)/.well-known/openid-credential-issuer": try response(TestIssuer.issuerMetadata()),
            "GET \(base)/.well-known/oauth-authorization-server/vci": try response(server),
            "POST \(tokenURL)": try response(["error": "invalid_grant"], status: 400),
        ]
        let tokenRequests = TokenRequestCounter()
        let http = WalletHTTP(testResponse: { request in
            let key = "\(request.httpMethod ?? "") \(request.url?.absoluteString ?? "")"
            guard let reply = replies[key] else { throw WalletError.network("Unexpected test request: \(key)") }
            if key == "POST \(tokenURL)" { await tokenRequests.record() }
            return reply
        })
        let client = OpenID4VCIClient(
            http: http, store: MemoryStore(),
            walletAttestationProvider: FlakyWalletAttestationProvider())
        let preview = try await client.preview(offer: link)

        await #expect(throws: WalletError.network("Temporary provider timeout.")) {
            try await client.issue(preview, transactionCode: nil)
        }
        #expect(await tokenRequests.count() == 0)
        await #expect(throws: WalletError.offerRejected) {
            try await client.issue(preview, transactionCode: nil)
        }
        #expect(await tokenRequests.count() == 1)
    }

    @Test func clientAttestationAndDPoPProofsRefreshAcrossExplicitChallenges() async throws {
        let base = TestIssuer.base
        let tokenEndpoint = base + "/vci/token"
        let credentialEndpoint = base + "/vci/credential"
        let offerURL = base + "/vci/offers/ref1"
        let encodedOfferURL = try #require(offerURL.addingPercentEncoding(withAllowedCharacters: .alphanumerics))
        let offerLink = "openid-credential-offer://?credential_offer_uri=\(encodedOfferURL)"
        let issuer = TestIssuer()
        let holder = TestSigner(tag: "com.authrim.keyring.vc.holder.attestation-test", key: P256.Signing.PrivateKey())
        let store = MemoryStore()
        let fixedNow = Date.now
        let receivedClientKey = Box<PublicJWK?>(nil)
        let provider = MockWalletAttestationProvider(receivedClientKey: receivedClientKey)

        StubURLProtocol.on("GET", offerURL, json: TestIssuer.offerJSON())
        StubURLProtocol.on("GET", base + "/.well-known/openid-credential-issuer", json: TestIssuer.issuerMetadata())
        var server = TestIssuer.serverMetadata()
        server["dpop_signing_alg_values_supported"] = ["ES256"]
        server["token_endpoint_auth_methods_supported"] = ["attest_jwt_client_auth", "none"]
        StubURLProtocol.on("GET", base + "/.well-known/oauth-authorization-server/vci", json: server)
        StubURLProtocol.on("POST", tokenEndpoint) { _ in
            switch StubURLProtocol.requests(to: tokenEndpoint).count {
            case 1:
                return .init(
                    status: 400,
                    headers: ["Content-Type": "application/json",
                              "OAuth-Client-Attestation-Challenge": "wallet-challenge"],
                    body: Data(#"{"error":"use_attestation_challenge"}"#.utf8))
            case 2:
                return .init(
                    status: 400,
                    headers: ["Content-Type": "application/json", "DPoP-Nonce": "as-nonce"],
                    body: Data(#"{"error":"use_dpop_nonce"}"#.utf8))
            default:
                return .init(headers: ["Content-Type": "application/json"],
                             body: Data(#"{"access_token":"AT","token_type":"DPoP"}"#.utf8))
            }
        }
        StubURLProtocol.on("POST", base + "/vci/nonce", json: ["c_nonce": "credential-nonce"])
        StubURLProtocol.on("GET", base + "/.well-known/jwt-vc-issuer", json: issuer.jwks())
        StubURLProtocol.on("POST", credentialEndpoint) { _ in
            guard let credential = try? issuer.sdJwt(holder: holder.publicJWK),
                  let body = try? JSONSerialization.data(withJSONObject: ["credentials": [["credential": credential]]])
            else { return .init(status: 500) }
            return .init(headers: ["Content-Type": "application/json"], body: body)
        }

        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            makeKey: { _ in holder }, deleteKey: { _ in },
            now: { fixedNow }, languages: { ["en"] },
            walletAttestationProvider: provider)
        let preview = try await client.preview(offer: offerLink)
        let saved = try await client.issue(preview, transactionCode: "123456")
        #expect(store.items == [saved])

        let tokenRequests = StubURLProtocol.requests(to: tokenEndpoint)
        #expect(tokenRequests.count == 3)
        let clientKey = try #require(receivedClientKey.value)
        let publicKey = try #require(clientKey.cryptoKey)
        let attestationHeader = try #require(tokenRequests.first?.value(forHTTPHeaderField: "OAuth-Client-Attestation"))
        let attestation = try #require(JWS.parse(attestationHeader))
        #expect(attestation.header["typ"] as? String == "oauth-client-attestation+jwt")
        let confirmed = try #require((attestation.payload["cnf"] as? [String: Any])?["jwk"] as? [String: String])
        #expect(confirmed == clientKey.proofMembers)

        var popJTIs: [String] = []
        var dpopJTIs: [String] = []
        for (index, request) in tokenRequests.enumerated() {
            #expect(request.value(forHTTPHeaderField: "OAuth-Client-Attestation") == attestationHeader)
            let popText = try #require(request.value(forHTTPHeaderField: "OAuth-Client-Attestation-PoP"))
            let dpopText = try #require(request.value(forHTTPHeaderField: "DPoP"))
            let pop = try #require(JWS.parse(popText))
            let dpop = try #require(JWS.parse(dpopText))
            #expect(pop.header["typ"] as? String == "oauth-client-attestation-pop+jwt")
            #expect(pop.payload["iss"] as? String == "wallet.example")
            #expect(pop.payload["aud"] as? String == base + "/vci")
            #expect(pop.payload["iat"] as? Int == Int(fixedNow.timeIntervalSince1970))
            #expect((dpop.header["jwk"] as? [String: String]) == clientKey.proofMembers)
            #expect(JWS.verifyES256(pop, with: publicKey))
            #expect(JWS.verifyES256(dpop, with: publicKey))
            popJTIs.append(try #require(pop.payload["jti"] as? String))
            dpopJTIs.append(try #require(dpop.payload["jti"] as? String))
            #expect(dpop.payload["nonce"] as? String == (index == 2 ? "as-nonce" : nil))
            #expect(pop.payload["challenge"] as? String == (index == 0 ? nil : "wallet-challenge"))
        }
        #expect(Set(popJTIs).count == 3)
        #expect(Set(dpopJTIs).count == 3)
        let credentialRequest = try #require(StubURLProtocol.requests(to: credentialEndpoint).first)
        #expect(credentialRequest.value(forHTTPHeaderField: "Authorization") == "DPoP AT")
        #expect(credentialRequest.value(forHTTPHeaderField: "OAuth-Client-Attestation") == nil)
    }
}
}

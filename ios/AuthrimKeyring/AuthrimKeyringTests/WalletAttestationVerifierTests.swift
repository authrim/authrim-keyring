import CryptoKit
import Foundation
import Testing
@testable import AuthrimKeyring

private enum WalletAttestationFixture {
    static let root = KeyAttestationVerifierTests.root
    static let leaf = KeyAttestationVerifierTests.leaf
    static let scalar = KeyAttestationVerifierTests.scalar
    static let provider = URL(string: "https://wallet-provider.eudiw.dev")!
    static let issuer = URL(string: "https://issuer.eudiw.dev")!

    static func keys() throws -> (root: Data, signer: P256.Signing.PrivateKey, client: PublicJWK) {
        let rootDER = try #require(Data(base64Encoded: root))
        let scalarBytes = try #require(Data(base64Encoded: scalar))
        let signer = try P256.Signing.PrivateKey(rawRepresentation: scalarBytes)
        let client = try #require(PublicJWK(x963: P256.Signing.PrivateKey().publicKey.x963Representation))
        return (rootDER, signer, client)
    }

    static func jwt(
        signer: P256.Signing.PrivateKey, client: PublicJWK, now: Date,
        headerChanges: [String: Any] = [:], payloadChanges: [String: Any] = [:],
        omittingClaims: Set<String> = []
    ) throws -> String {
        var header: [String: Any] = [
            "typ": "oauth-client-attestation+jwt", "alg": "ES256", "x5c": [leaf],
        ]
        var payload: [String: Any] = [
            "iss": provider.absoluteString, "sub": "wallet-test",
            "iat": Int(now.timeIntervalSince1970) - 10,
            "nbf": Int(now.timeIntervalSince1970) - 10,
            "exp": Int(now.timeIntervalSince1970) + 300,
            "cnf": ["jwk": client.proofMembers],
        ]
        header.merge(headerChanges) { _, new in new }
        payload.merge(payloadChanges) { _, new in new }
        for claim in omittingClaims { payload.removeValue(forKey: claim) }
        return try JWS.make(header: header, payload: payload) { input in
            try signer.signature(for: input).rawRepresentation
        }
    }
}

@Suite
struct WalletAttestationVerifierTests {
    private let fixedNow = Date(timeIntervalSince1970: 1_794_182_400)

    @Test func acceptsVerifiedWalletClientID() throws {
        let f = try WalletAttestationFixture.keys()
        let jwt = try WalletAttestationFixture.jwt(signer: f.signer, client: f.client, now: fixedNow)
        let result = try WalletAttestationVerifier.validate(
            jwt, clientKey: f.client, providerIssuer: WalletAttestationFixture.provider,
            trustedRootDER: [f.root], now: fixedNow)
        #expect(result.jwt == jwt)
        #expect(result.clientID == "wallet-test")
    }

    @Test func acceptsAttestationWithoutOptionalTimeClaims() throws {
        let f = try WalletAttestationFixture.keys()
        for omitted in [Set(["iat"]), Set(["nbf"]), Set(["iat", "nbf"])] {
            let jwt = try WalletAttestationFixture.jwt(
                signer: f.signer, client: f.client, now: fixedNow, omittingClaims: omitted)
            let result = try WalletAttestationVerifier.validate(
                jwt, clientKey: f.client, providerIssuer: WalletAttestationFixture.provider,
                trustedRootDER: [f.root], now: fixedNow)
            #expect(result.jwt == jwt)
        }
    }

    @Test func rejectsMalformedOptionalTimeClaimsAndMissingExpiration() throws {
        let f = try WalletAttestationFixture.keys()
        for claim in ["iat", "nbf"] {
            let jwt = try WalletAttestationFixture.jwt(
                signer: f.signer, client: f.client, now: fixedNow,
                payloadChanges: [claim: "invalid"])
            #expect(throws: WalletAttestationValidationError.invalidTime) {
                try WalletAttestationVerifier.validate(
                    jwt, clientKey: f.client, providerIssuer: WalletAttestationFixture.provider,
                    trustedRootDER: [f.root], now: fixedNow)
            }
        }
        let withoutExpiration = try WalletAttestationFixture.jwt(
            signer: f.signer, client: f.client, now: fixedNow, omittingClaims: ["exp"])
        #expect(throws: WalletAttestationValidationError.invalidTime) {
            try WalletAttestationVerifier.validate(
                withoutExpiration, clientKey: f.client, providerIssuer: WalletAttestationFixture.provider,
                trustedRootDER: [f.root], now: fixedNow)
        }
    }

    @Test func rejectsWrongClientKeyAndProvider() throws {
        let f = try WalletAttestationFixture.keys()
        let other = try #require(PublicJWK(x963: P256.Signing.PrivateKey().publicKey.x963Representation))
        let jwt = try WalletAttestationFixture.jwt(signer: f.signer, client: f.client, now: fixedNow)
        #expect(throws: WalletAttestationValidationError.wrongClientKey) {
            try WalletAttestationVerifier.validate(
                jwt, clientKey: other, providerIssuer: WalletAttestationFixture.provider,
                trustedRootDER: [f.root], now: fixedNow)
        }
        #expect(throws: WalletAttestationValidationError.wrongProvider) {
            try WalletAttestationVerifier.validate(
                jwt, clientKey: f.client, providerIssuer: URL(string: "https://other-provider.example")!,
                trustedRootDER: [f.root], now: fixedNow)
        }
    }

    @Test func rejectsForgedSignatureAndExpiredAttestation() throws {
        let f = try WalletAttestationFixture.keys()
        let forged = try WalletAttestationFixture.jwt(
            signer: P256.Signing.PrivateKey(), client: f.client, now: fixedNow)
        #expect(throws: WalletAttestationValidationError.invalidSignature) {
            try WalletAttestationVerifier.validate(
                forged, clientKey: f.client, providerIssuer: WalletAttestationFixture.provider,
                trustedRootDER: [f.root], now: fixedNow)
        }
        let expired = try WalletAttestationFixture.jwt(
            signer: f.signer, client: f.client, now: fixedNow,
            payloadChanges: ["exp": Int(fixedNow.timeIntervalSince1970) - 1])
        #expect(throws: WalletAttestationValidationError.invalidTime) {
            try WalletAttestationVerifier.validate(
                expired, clientKey: f.client, providerIssuer: WalletAttestationFixture.provider,
                trustedRootDER: [f.root], now: fixedNow)
        }
    }

    @Test func refusesSigningCertificateAsTrustAnchor() throws {
        let f = try WalletAttestationFixture.keys()
        let jwt = try WalletAttestationFixture.jwt(signer: f.signer, client: f.client, now: fixedNow)
        let leafDER = try #require(Data(base64Encoded: WalletAttestationFixture.leaf))
        #expect(throws: WalletAttestationValidationError.untrustedCertificate) {
            try WalletAttestationVerifier.validate(
                jwt, clientKey: f.client, providerIssuer: WalletAttestationFixture.provider,
                trustedRootDER: [leafDER], now: fixedNow)
        }
    }
}

#if DEBUG
extension StubbedNetworkTests {
    @Suite(.serialized)
    struct WalletAttestationAdapterTests {
        private static let providerURL = "https://wallet-provider.eudiw.dev/wallet-instance-attestation/jwk"
        private static let trustURL = "https://trust-validator.eudiw.dev/trust"

        init() { StubURLProtocol.reset() }

        @Test func requestsOnlyPublicKeyAndAcceptsTrustedAnchor() async throws {
            let f = try WalletAttestationFixture.keys()
            let jwt = try WalletAttestationFixture.jwt(signer: f.signer, client: f.client, now: .now)
            StubURLProtocol.on("POST", Self.providerURL, json: ["walletInstanceAttestation": jwt])
            StubURLProtocol.on("POST", Self.trustURL, json: [
                "trusted": true,
                "trustAnchor": WalletAttestationFixture.root.trimmingCharacters(in: CharacterSet(charactersIn: "=")),
            ])
            let adapter = EUDITestWalletAttestationProvider(
                http: WalletHTTP(protocolClasses: [StubURLProtocol.self]))
            let result = try await adapter.attestation(for: f.client, issuer: WalletAttestationFixture.issuer)
            #expect(result.clientID == "wallet-test")

            let providerBody = try #require(StubURLProtocol.body(of: Self.providerURL))
            let providerRequest = try #require(
                JSONSerialization.jsonObject(with: providerBody) as? [String: Any])
            let jwk = try #require(providerRequest["jwk"] as? [String: String])
            #expect(jwk["alg"] == "ES256")
            #expect(jwk["x"] == f.client.x)
            #expect(jwk["y"] == f.client.y)
            #expect(jwk["d"] == nil)

            let trustBody = try #require(StubURLProtocol.body(of: Self.trustURL))
            let trustRequest = try #require(
                JSONSerialization.jsonObject(with: trustBody) as? [String: Any])
            #expect(trustRequest["verificationContext"] as? String == "WalletProviderAttestation")
            #expect(trustRequest["chain"] as? [String] == [WalletAttestationFixture.leaf])
        }

        @Test func rejectsOtherIssuerWithoutNetwork() async throws {
            let f = try WalletAttestationFixture.keys()
            let adapter = EUDITestWalletAttestationProvider(
                http: WalletHTTP(protocolClasses: [StubURLProtocol.self]))
            let other = URL(string: "https://another-issuer.example")!
            #expect(!adapter.supports(issuer: other))
            await #expect(throws: WalletError.unsupportedKeyAttestation) {
                try await adapter.attestation(for: f.client, issuer: other)
            }
            #expect(StubURLProtocol.requests(to: Self.providerURL).isEmpty)
            #expect(StubURLProtocol.requests(to: Self.trustURL).isEmpty)
        }
    }
}
#endif

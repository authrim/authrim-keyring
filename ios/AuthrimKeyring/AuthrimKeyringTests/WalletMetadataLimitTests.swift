import Foundation
import Testing
@testable import AuthrimKeyring

extension StubbedNetworkTests {
@Suite(.serialized)
struct WalletMetadataLimitTests {
    init() { StubURLProtocol.reset() }

    private func resolveWithServer(_ server: [String: Any], canAuthenticate: Bool = false) async throws -> VerifiedIssuer {
        let offer = try CredentialOfferParser.parse(
            json: JSONSerialization.data(withJSONObject: TestIssuer.offerJSON()))
        StubURLProtocol.on("GET", TestIssuer.base + "/.well-known/openid-credential-issuer",
                           json: TestIssuer.issuerMetadata())
        StubURLProtocol.on("GET", TestIssuer.base + "/.well-known/oauth-authorization-server/vci",
                           json: server)
        return try await IssuerMetadata.resolve(
            offer: offer, http: WalletHTTP(protocolClasses: [StubURLProtocol.self]),
            preferredLanguages: ["en"], canAuthenticateWithWalletAttestation: canAuthenticate)
    }

    @Test func acceptsLargeIssuerMetadataWithinDedicatedLimit() async throws {
        let offer = try CredentialOfferParser.parse(
            json: JSONSerialization.data(withJSONObject: TestIssuer.offerJSON()))
        var metadata = TestIssuer.issuerMetadata()
        metadata["unused_extension"] = String(repeating: "x", count: WalletHTTP.jsonLimit)
        let data = try JSONSerialization.data(withJSONObject: metadata)
        #expect(data.count > WalletHTTP.jsonLimit)
        #expect(data.count < WalletHTTP.issuerMetadataLimit)

        StubURLProtocol.on("GET", TestIssuer.base + "/.well-known/openid-credential-issuer", json: metadata)
        StubURLProtocol.on("GET", TestIssuer.base + "/.well-known/oauth-authorization-server/vci",
                           json: TestIssuer.serverMetadata())

        let issuer = try await IssuerMetadata.resolve(
            offer: offer, http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), preferredLanguages: ["en"])
        #expect(issuer.issuer.absoluteString == TestIssuer.base)
    }

    @Test func rejectsIssuerMetadataBeyondDedicatedLimit() async throws {
        let offer = try CredentialOfferParser.parse(
            json: JSONSerialization.data(withJSONObject: TestIssuer.offerJSON()))
        var metadata = TestIssuer.issuerMetadata()
        metadata["unused_extension"] = String(repeating: "x", count: WalletHTTP.issuerMetadataLimit)
        StubURLProtocol.on("GET", TestIssuer.base + "/.well-known/openid-credential-issuer", json: metadata)

        await #expect(throws: WalletError.outcomeUnknown("The response is too large.")) {
            try await IssuerMetadata.resolve(
                offer: offer, http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), preferredLanguages: ["en"])
        }
    }

    @Test(arguments: ["credential_request_encryption", "credential_response_encryption"])
    func rejectsRequiredEncryptionBeforeRedeemingOffer(name: String) async throws {
        let offer = try CredentialOfferParser.parse(
            json: JSONSerialization.data(withJSONObject: TestIssuer.offerJSON()))
        var metadata = TestIssuer.issuerMetadata()
        metadata[name] = ["encryption_required": true]
        StubURLProtocol.on("GET", TestIssuer.base + "/.well-known/openid-credential-issuer", json: metadata)

        await #expect(throws: WalletError.unsupportedCredentialEncryption) {
            try await IssuerMetadata.resolve(
                offer: offer, http: WalletHTTP(protocolClasses: [StubURLProtocol.self]),
                preferredLanguages: ["en"])
        }
        #expect(StubURLProtocol.requests(to: TestIssuer.base + "/vci/token").isEmpty)
    }

    @Test func rejectsMalformedEncryptionRequirement() async throws {
        let offer = try CredentialOfferParser.parse(
            json: JSONSerialization.data(withJSONObject: TestIssuer.offerJSON()))
        var metadata = TestIssuer.issuerMetadata()
        metadata["credential_request_encryption"] = ["encryption_required": "false"]
        StubURLProtocol.on("GET", TestIssuer.base + "/.well-known/openid-credential-issuer", json: metadata)

        await #expect(throws: WalletError.invalidIssuer("The credential_request_encryption metadata is malformed.")) {
            try await IssuerMetadata.resolve(
                offer: offer, http: WalletHTTP(protocolClasses: [StubURLProtocol.self]),
                preferredLanguages: ["en"])
        }
    }

    @Test func acceptsPictureSizedCredentialResponse() async throws {
        let endpoint = URL(string: TestIssuer.base + "/vci/credential")!
        let picture = String(repeating: "A", count: 96 * 1024)
        StubURLProtocol.on("POST", endpoint.absoluteString, json: [
            "credentials": [["credential": picture]],
        ])

        let response = try await WalletHTTP(protocolClasses: [StubURLProtocol.self]).send(
            endpoint, method: "POST", maxBytes: WalletHTTP.credentialLimit, origin: endpoint)
        #expect(response.status == 200)
        #expect(response.data.count > 32 * 1024)
    }

    @Test func omittedGrantListDoesNotAdvertisePreAuthorizedCode() async throws {
        var server = TestIssuer.serverMetadata()
        server.removeValue(forKey: "grant_types_supported")
        await #expect(throws: WalletError.invalidIssuer("The authorization server does not support the pre-authorized code grant.")) {
            try await resolveWithServer(server)
        }
        #expect(StubURLProtocol.requests(to: TestIssuer.base + "/vci/token").isEmpty)
    }

    @Test func malformedGrantListIsRejected() async throws {
        var server = TestIssuer.serverMetadata()
        server["grant_types_supported"] = [1]
        await #expect(throws: WalletError.invalidIssuer("The authorization server grant list is malformed.")) {
            try await resolveWithServer(server)
        }
    }

    @Test func omittedAnonymousAccessRequiresUsableWalletAuthentication() async throws {
        var server = TestIssuer.serverMetadata()
        server.removeValue(forKey: "pre-authorized_grant_anonymous_access_supported")
        await #expect(throws: WalletError.invalidIssuer("The authorization server requires client authentication this wallet cannot provide.")) {
            try await resolveWithServer(server)
        }

        server["token_endpoint_auth_methods_supported"] = ["attest_jwt_client_auth"]
        server["dpop_signing_alg_values_supported"] = ["ES256"]
        let verified = try await resolveWithServer(server, canAuthenticate: true)
        #expect(verified.supportsWalletAttestation)
        #expect(verified.supportsDPoP)
    }

    @Test func malformedAnonymousAccessPolicyIsRejected() async throws {
        var server = TestIssuer.serverMetadata()
        server["pre-authorized_grant_anonymous_access_supported"] = 1
        await #expect(throws: WalletError.invalidIssuer("The anonymous pre-authorized grant policy is malformed.")) {
            try await resolveWithServer(server)
        }
    }
}
}

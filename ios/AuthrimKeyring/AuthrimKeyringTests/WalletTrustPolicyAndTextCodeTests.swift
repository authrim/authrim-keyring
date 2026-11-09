import CryptoKit
import Foundation
import Testing
@testable import AuthrimKeyring

extension StubbedNetworkTests {
@Suite(.serialized)
struct WalletTrustPolicyAndTextCodeTests {
    private let issuer = TestIssuer()
    private let signer = TestSigner(tag: "holder.test", key: P256.Signing.PrivateKey())
    private let store = MemoryStore()

    init() { StubURLProtocol.reset() }

    private func link(_ offer: [String: Any], scheme: String = "openid-credential-offer") throws -> String {
        let data = try JSONSerialization.data(withJSONObject: offer)
        let encoded = try #require(String(decoding: data, as: UTF8.self)
            .addingPercentEncoding(withAllowedCharacters: .alphanumerics))
        return "\(scheme)://credential_offer?credential_offer=\(encoded)"
    }

    private func metadata() {
        StubURLProtocol.on("GET", TestIssuer.base + "/.well-known/openid-credential-issuer",
                           json: TestIssuer.issuerMetadata())
        var server = TestIssuer.serverMetadata()
        server["pre-authorized_grant_anonymous_access_supported"] = true
        StubURLProtocol.on("GET", TestIssuer.base + "/.well-known/oauth-authorization-server/vci",
                           json: server)
    }

    @Test func ordinaryWrapperCannotBypassConfiguredIssuerCertificatePolicy() async throws {
        metadata()
        StubURLProtocol.on("POST", TestIssuer.base + "/vci/token",
                           json: ["access_token": "AT", "token_type": "Bearer"])
        StubURLProtocol.on("POST", TestIssuer.base + "/vci/nonce", json: ["c_nonce": "N"])
        let credential = try issuer.sdJwt(holder: signer.publicJWK)
        StubURLProtocol.on("POST", TestIssuer.base + "/vci/credential",
                           json: ["credentials": [["credential": credential]]])
        let root = try #require(Data(base64Encoded: IssuerX509VerifierTests.root))
        let signer = signer
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            makeKey: { _ in signer }, deleteKey: { _ in }, languages: { ["en"] },
            issuerCertificateTrustSource: WalletTestIssuerX509TrustSource(root: root, vcts: [TestIssuer.vct]))

        let preview = try await client.preview(offer: link(TestIssuer.offerJSON()))
        await #expect(throws: WalletError.offerConsumed("The HAIP credential has no supported issuer certificate chain.")) {
            try await client.issue(preview, transactionCode: "123456")
        }
        #expect(store.items.isEmpty)
        #expect(StubURLProtocol.requests(to: TestIssuer.base + "/.well-known/jwt-vc-issuer").isEmpty)
    }

    @Test func clientSendsTextTransactionCodeWithItsSpaces() async throws {
        metadata()
        StubURLProtocol.on("POST", TestIssuer.base + "/vci/token",
                           json: ["error": "invalid_grant"], status: 400)
        var offer = TestIssuer.offerJSON()
        var grants = try #require(offer["grants"] as? [String: Any])
        var grant = try #require(grants[CredentialOfferParser.preAuthorizedGrant] as? [String: Any])
        grant["tx_code"] = ["input_mode": "text", "length": 4]
        grants[CredentialOfferParser.preAuthorizedGrant] = grant
        offer["grants"] = grants
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            makeKey: { _ in signer }, deleteKey: { _ in }, languages: { ["en"] })

        let preview = try await client.preview(offer: link(offer))
        await #expect(throws: WalletError.offerRejected) {
            try await client.issue(preview, transactionCode: " AB ")
        }
        let body = try #require(StubURLProtocol.body(of: TestIssuer.base + "/vci/token"))
        #expect(String(decoding: body, as: UTF8.self).contains("tx_code=%20AB%20"))
    }
}
}

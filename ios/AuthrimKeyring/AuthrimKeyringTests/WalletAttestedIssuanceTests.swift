import CryptoKit
import Foundation
import Testing
@testable import AuthrimKeyring

/// The suite shares StubURLProtocol's registry with the other network tests.
extension StubbedNetworkTests {
@Suite(.serialized)
struct WalletAttestedIssuanceTests {
    private static let base = TestIssuer.base
    private static let now = Date(timeIntervalSince1970: 1_794_182_400)
    private static let requirements = KeyAttestationRequirements(
        acceptedKeyStorage: ["iso_18045_high"],
        acceptedUserAuthentication: ["iso_18045_high"])

    init() { StubURLProtocol.reset() }

    private struct Context {
        let client: OpenID4VCIClient
        let offer: String
        let issuer: TestIssuer
        let root: Data
        let store: MemoryStore
        let created: Box<[TestSigner]>
        let deleted: Box<[String]>
        let trace: AttestationTrace
    }

    private func context(firstResponse: AttestationTrace.FirstResponse = .valid) throws -> Context {
        let root = try #require(Data(base64Encoded: KeyAttestationVerifierTests.root))
        let scalar = try #require(Data(base64Encoded: KeyAttestationVerifierTests.scalar))
        let trace = AttestationTrace(firstResponse: firstResponse)
        let store = MemoryStore()
        let created = Box<[TestSigner]>([])
        let deleted = Box<[String]>([])
        let issuer = TestIssuer()

        var metadata = TestIssuer.issuerMetadata()
        var configurations = try #require(metadata["credential_configurations_supported"] as? [String: Any])
        var admin = try #require(configurations["admin"] as? [String: Any])
        var proofTypes = try #require(admin["proof_types_supported"] as? [String: Any])
        var jwt = try #require(proofTypes["jwt"] as? [String: Any])
        jwt["key_attestations_required"] = [
            "key_storage": ["iso_18045_high"],
            "user_authentication": ["iso_18045_high"],
        ]
        proofTypes["jwt"] = jwt
        admin["proof_types_supported"] = proofTypes
        configurations["admin"] = admin
        metadata["credential_configurations_supported"] = configurations

        StubURLProtocol.on("GET", Self.base + "/.well-known/openid-credential-issuer", json: metadata)
        StubURLProtocol.on("GET", Self.base + "/.well-known/oauth-authorization-server/vci",
                           json: TestIssuer.serverMetadata())
        StubURLProtocol.on("POST", Self.base + "/vci/token") { _ in
            trace.record("token")
            return .init(headers: ["Content-Type": "application/json"],
                         body: Data(#"{"access_token":"AT","token_type":"Bearer"}"#.utf8))
        }
        StubURLProtocol.on("POST", Self.base + "/vci/nonce", json: ["c_nonce": "NONCE-1"])
        StubURLProtocol.on("GET", Self.base + "/.well-known/jwt-vc-issuer", json: issuer.jwks())
        let issuedAt = Self.now
        StubURLProtocol.on("POST", Self.base + "/vci/credential") { _ in
            guard let signer = created.value.last else { return .init(status: 500) }
            var options = TestIssuer.Options()
            options.iat = issuedAt
            options.exp = issuedAt.addingTimeInterval(3_600)
            guard let credential = try? issuer.sdJwt(holder: signer.publicJWK, options),
                  let body = try? JSONSerialization.data(withJSONObject: [
                    "credentials": [["credential": credential]],
                  ]) else { return .init(status: 500) }
            return .init(headers: ["Content-Type": "application/json"], body: body)
        }

        let offer = TestIssuer.offerJSON(txCode: false)
        let offerData = try JSONSerialization.data(withJSONObject: offer)
        let encoded = try #require(String(decoding: offerData, as: UTF8.self)
            .addingPercentEncoding(withAllowedCharacters: .alphanumerics))
        let link = "openid-credential-offer://?credential_offer=\(encoded)"
        let fixedTime = Self.now
        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            makeKey: { tag in
                let signer = TestSigner(tag: tag, key: P256.Signing.PrivateKey())
                created.value.append(signer)
                return signer
            },
            deleteKey: { deleted.value.append($0) },
            now: { fixedTime }, languages: { ["en"] },
            keyAttestationProvider: StubKeyAttestationProvider(scalar: scalar, trace: trace),
            keyAttestationTrustSource: StubKeyAttestationTrustSource(root: root, trace: trace))
        return Context(client: client, offer: link, issuer: issuer, root: root, store: store,
                       created: created, deleted: deleted, trace: trace)
    }

    @Test func validatesAttestationBeforeTokenAndSavesBoundCredential() async throws {
        let context = try context()
        let preview = try await context.client.preview(offer: context.offer)
        let stored = try await context.client.issue(preview, transactionCode: nil)

        #expect(context.trace.events == ["attestation", "trust", "token"])
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").count == 1)
        let signer = try #require(context.created.value.last)
        let bodyData = try #require(StubURLProtocol.body(of: Self.base + "/vci/credential"))
        let body = try #require(JSONSerialization.jsonObject(with: bodyData) as? [String: Any])
        let proof = try #require(((body["proofs"] as? [String: Any])?["jwt"] as? [String])?.first)
        let parts = try #require(JWS.parse(proof))
        let attestation = try #require(parts.header["key_attestation"] as? String)
        #expect(parts.payload["nonce"] as? String == "NONCE-1")
        #expect(parts.payload["aud"] as? String == Self.base)
        #expect((parts.header["jwk"] as? [String: String]) == signer.publicJWK.proofMembers)
        #expect(JWS.verifyES256(parts, with: signer.key.publicKey))
        #expect(try KeyAttestationVerifier.validate(
            attestation, holderKey: signer.publicJWK, nonce: "NONCE-1",
            requirements: Self.requirements, trustedRootDER: [context.root], now: Self.now) == attestation)
        #expect(context.store.items == [stored])
        #expect(stored.keyTag == signer.tag)
        #expect(stored.confirmationCode == signer.publicJWK.confirmationCode)
        #expect(context.deleted.value.isEmpty)
    }

    @Test func temporaryProviderFailureDeletesKeyAndLeavesOfferRetryable() async throws {
        let context = try context(firstResponse: .unavailable)
        let preview = try await context.client.preview(offer: context.offer)

        do {
            _ = try await context.client.issue(preview, transactionCode: nil)
            Issue.record("Expected the first attestation request to fail")
        } catch let error as WalletError {
            #expect(error == .network("Temporary wallet-provider failure."))
            #expect(error.canRetry)
        }
        #expect(context.trace.events == ["attestation"])
        #expect(context.created.value.count == 1)
        #expect(context.deleted.value == context.created.value.map(\.tag))
        #expect(context.store.items.isEmpty)
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").isEmpty)

        let stored = try await context.client.issue(preview, transactionCode: nil)
        #expect(context.trace.events == ["attestation", "attestation", "trust", "token"])
        #expect(context.created.value.count == 2)
        #expect(context.deleted.value == [context.created.value[0].tag])
        #expect(context.store.items == [stored])
        #expect(stored.keyTag == context.created.value[1].tag)
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").count == 1)
    }

    @Test func rejectsAttestationForAnotherHolderBeforeToken() async throws {
        let context = try context(firstResponse: .wrongHolderKey)
        let preview = try await context.client.preview(offer: context.offer)

        await #expect(throws: WalletError.invalidIssuer(
            "The wallet provider key attestation could not be verified.")) {
            try await context.client.issue(preview, transactionCode: nil)
        }
        #expect(context.trace.events == ["attestation", "trust"])
        #expect(context.created.value.count == 1)
        #expect(context.deleted.value == context.created.value.map(\.tag))
        #expect(context.store.items.isEmpty)
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").isEmpty)
    }

    @Test func attestsEachDatasetWithItsOwnNonceAndHolderKey() async throws {
        let context = try context()
        let tokenURL = Self.base + "/vci/token"
        let nonceURL = Self.base + "/vci/nonce"
        let credentialURL = Self.base + "/vci/credential"
        StubURLProtocol.on("POST", tokenURL) { _ in
            context.trace.record("token")
            let body = try! JSONSerialization.data(withJSONObject: [
                "access_token": "AT", "token_type": "Bearer",
                "authorization_details": [[
                    "type": "openid_credential", "credential_configuration_id": "admin",
                    "credential_identifiers": ["dataset-1", "dataset-2"],
                ]],
            ])
            return .init(headers: ["Content-Type": "application/json"], body: body)
        }
        StubURLProtocol.on("POST", nonceURL) { _ in
            let count = StubURLProtocol.requests(to: nonceURL).count
            return .init(headers: ["Content-Type": "application/json"],
                         body: Data("{\"c_nonce\":\"NONCE-\(count)\"}".utf8))
        }
        let received = Box<[String]>([])
        let issuer = context.issuer
        StubURLProtocol.on("POST", credentialURL) { _ in
            guard let data = StubURLProtocol.body(of: credentialURL),
                  let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                  let identifier = object["credential_identifier"] as? String,
                  let proof = ((object["proofs"] as? [String: Any])?["jwt"] as? [String])?.first,
                  let parts = JWS.parse(proof),
                  let signer = context.created.value.last,
                  let attestation = parts.header["key_attestation"] as? String,
                  let ka = JWS.parse(attestation),
                  let nonce = parts.payload["nonce"] as? String,
                  nonce == "NONCE-\(received.value.count + 1)",
                  ka.payload["nonce"] as? String == nonce,
                  (parts.header["jwk"] as? [String: String]) == signer.publicJWK.proofMembers
            else { return .init(status: 400) }
            received.value.append(identifier)
            var options = TestIssuer.Options()
            options.iat = Self.now
            options.exp = Self.now.addingTimeInterval(3_600)
            let credential = try! issuer.sdJwt(holder: signer.publicJWK, options)
            let body = try! JSONSerialization.data(withJSONObject: ["credentials": [["credential": credential]]])
            return .init(headers: ["Content-Type": "application/json"], body: body)
        }
        let preview = try await context.client.preview(offer: context.offer)
        let saved = try await context.client.issueAll(
            preview, selectedConfigurationIds: ["admin"], transactionCode: nil)
        #expect(saved.count == 2)
        #expect(received.value == ["dataset-1", "dataset-2"])
        #expect(context.trace.events == ["attestation", "trust", "token", "attestation", "trust"])
        #expect(context.created.value.count == 2)
        #expect(Set(saved.map(\.keyTag)).count == 2)
        #expect(context.deleted.value.isEmpty)
        #expect(context.store.items == saved)
        #expect(StubURLProtocol.requests(to: nonceURL).count == 2)
        #expect(StubURLProtocol.requests(to: tokenURL).count == 1)
    }

    @Test func expiredCredentialNonceRefreshesAttestationWithoutRedeemingCodeAgain() async throws {
        let context = try context()
        let nonceURL = Self.base + "/vci/nonce"
        let credentialURL = Self.base + "/vci/credential"
        let sentNonces = Box<[String]>([])
        StubURLProtocol.on("POST", nonceURL) { _ in
            let count = StubURLProtocol.requests(to: nonceURL).count
            return .init(headers: ["Content-Type": "application/json"],
                         body: Data("{\"c_nonce\":\"NONCE-\(count)\"}".utf8))
        }
        let issuer = context.issuer
        StubURLProtocol.on("POST", credentialURL) { _ in
            guard let data = StubURLProtocol.body(of: credentialURL),
                  let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                  let proof = ((object["proofs"] as? [String: Any])?["jwt"] as? [String])?.first,
                  let parts = JWS.parse(proof),
                  let ka = (parts.header["key_attestation"] as? String).flatMap(JWS.parse),
                  let proofNonce = parts.payload["nonce"] as? String,
                  ka.payload["nonce"] as? String == proofNonce
            else { return .init(status: 400) }
            sentNonces.value.append(proofNonce)
            if StubURLProtocol.requests(to: credentialURL).count == 1 {
                return .init(status: 400, headers: ["Content-Type": "application/json"],
                             body: Data(#"{"error":"invalid_nonce"}"#.utf8))
            }
            guard let signer = context.created.value.last else { return .init(status: 400) }
            var options = TestIssuer.Options()
            options.iat = Self.now
            options.exp = Self.now.addingTimeInterval(3_600)
            let credential = try! issuer.sdJwt(holder: signer.publicJWK, options)
            let response = try! JSONSerialization.data(withJSONObject: ["credentials": [["credential": credential]]])
            return .init(headers: ["Content-Type": "application/json"], body: response)
        }
        let preview = try await context.client.preview(offer: context.offer)
        let saved = try await context.client.issue(preview, transactionCode: nil)
        #expect(context.store.items == [saved])
        #expect(context.created.value.count == 1)
        #expect(context.deleted.value.isEmpty)
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/token").count == 1)
        #expect(StubURLProtocol.requests(to: nonceURL).count == 2)
        #expect(StubURLProtocol.requests(to: credentialURL).count == 2)
        #expect(sentNonces.value == ["NONCE-1", "NONCE-2"])
        #expect(context.trace.events == ["attestation", "trust", "token", "attestation", "trust"])
    }
}
}

nonisolated private final class AttestationTrace: @unchecked Sendable {
    enum FirstResponse { case valid, unavailable, wrongHolderKey }

    private let lock = NSLock()
    private var recorded: [String] = []
    private var response: FirstResponse

    init(firstResponse: FirstResponse) { response = firstResponse }

    var events: [String] {
        lock.lock(); defer { lock.unlock() }
        return recorded
    }

    func record(_ event: String) {
        lock.lock(); defer { lock.unlock() }
        recorded.append(event)
    }

    func nextProviderResponse() -> FirstResponse {
        lock.lock(); defer { lock.unlock() }
        recorded.append("attestation")
        let next = response
        response = .valid
        return next
    }
}

nonisolated private struct StubKeyAttestationProvider: KeyAttestationProvider {
    let scalar: Data
    let trace: AttestationTrace

    func supports(issuer: URL) -> Bool { issuer.absoluteString == TestIssuer.base }

    func attestation(for holderKey: PublicJWK, nonce: String?, issuer: URL) async throws -> String {
        guard supports(issuer: issuer), let nonce, nonce.hasPrefix("NONCE-") else {
            throw WalletError.unsupportedKeyAttestation
        }
        let response = trace.nextProviderResponse()
        if case .unavailable = response {
            throw WalletError.network("Temporary wallet-provider failure.")
        }
        let attestedKey: PublicJWK
        if case .wrongHolderKey = response {
            attestedKey = PublicJWK(x963: P256.Signing.PrivateKey().publicKey.x963Representation)!
        } else {
            attestedKey = holderKey
        }
        let signer = try P256.Signing.PrivateKey(rawRepresentation: scalar)
        let header: [String: Any] = [
            "alg": "ES256", "typ": "key-attestation+jwt", "x5c": [KeyAttestationVerifierTests.leaf],
        ]
        let payload: [String: Any] = [
            "iat": 1_794_182_390, "exp": 1_794_186_000,
            "nonce": nonce,
            "attested_keys": [attestedKey.proofMembers],
            "key_storage": ["iso_18045_high"],
            "user_authentication": ["iso_18045_high"],
        ]
        return try JWS.make(header: header, payload: payload) {
            try signer.signature(for: $0).rawRepresentation
        }
    }
}

nonisolated private struct StubKeyAttestationTrustSource: KeyAttestationTrustSource {
    let root: Data
    let trace: AttestationTrace

    func trustedRoots(for attestation: String, issuer: URL) async throws -> [Data] {
        guard issuer.absoluteString == TestIssuer.base, JWS.parse(attestation) != nil else {
            throw WalletError.invalidIssuer("The test attestation is malformed.")
        }
        trace.record("trust")
        return [root]
    }
}

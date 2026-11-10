import CryptoKit
import Foundation
import Testing
@testable import AuthrimKeyring

/// Exercises the combined HAIP pre-authorized path with two attested holder keys.
extension StubbedNetworkTests {
@Suite(.serialized)
struct WalletAttestedMultiIssuanceTests {
    private static let base = TestIssuer.base
    private static let now = Date(timeIntervalSince1970: 1_794_182_400)
    private static let diploma = "eu.europa.ec.eudi.diploma_vc_sd_jwt"
    private static let learning = "eu.europa.ec.eudi.learning_credential_vc_sd_jwt"
    private static let ids = [diploma, learning]
    private static let vcts = [
        "urn:eu.europa.ec.eudi:diploma:1:1",
        "urn:eu.europa.ec.eudi:learning:credential:1",
    ]
    private static let assurance = KeyAttestationRequirements(
        acceptedKeyStorage: ["iso_18045_high"],
        acceptedUserAuthentication: ["iso_18045_high"])

    init() { StubURLProtocol.reset() }

    @Test(arguments: ["haip-vci", "openid-credential-offer"])
    func savesTwoAttestedCredentialsWithOneDPoPToken(scheme: String) async throws {
        let root = try #require(Data(base64Encoded: KeyAttestationVerifierTests.root))
        let scalar = try #require(Data(base64Encoded: KeyAttestationVerifierTests.scalar))
        let issuerRoot = try #require(Data(base64Encoded: IssuerX509VerifierTests.root))
        let issuerScalar = try P256.Signing.PrivateKey(
            rawRepresentation: #require(Data(base64Encoded: IssuerX509VerifierTests.scalar)))
        let issuer = TestIssuer()
        let store = MemoryStore()
        let created = Box<[TestSigner]>([])
        let attestedKeys = Box<[PublicJWK]>([])
        let clientKey = Box<PublicJWK?>(nil)
        let credentialBodies = Box<[Data]>([])
        let deleted = Box<[String]>([])
        let fixedNow = Self.now
        let tokenURL = Self.base + "/vci/token"
        let credentialURL = Self.base + "/vci/credential"

        var metadata = TestIssuer.issuerMetadata()
        let original = try #require((metadata["credential_configurations_supported"] as? [String: Any])?["admin"] as? [String: Any])
        var configurations: [String: Any] = [:]
        for (index, id) in Self.ids.enumerated() {
            var configuration = original
            configuration["vct"] = Self.vcts[index]
            configuration["scope"] = id
            configuration["credential_metadata"] = ["display": [["name": index == 0 ? "Diploma" : "Learning credential", "locale": "en"]]]
            var proofTypes = try #require(configuration["proof_types_supported"] as? [String: Any])
            var jwt = try #require(proofTypes["jwt"] as? [String: Any])
            jwt["key_attestations_required"] = [
                "key_storage": ["iso_18045_high"],
                "user_authentication": ["iso_18045_high"],
            ]
            proofTypes["jwt"] = jwt
            configuration["proof_types_supported"] = proofTypes
            configurations[id] = configuration
        }
        metadata["credential_configurations_supported"] = configurations
        StubURLProtocol.on("GET", Self.base + "/.well-known/openid-credential-issuer", json: metadata)

        var server = TestIssuer.serverMetadata()
        server["dpop_signing_alg_values_supported"] = ["ES256"]
        server["token_endpoint_auth_methods_supported"] = ["attest_jwt_client_auth"]
        StubURLProtocol.on("GET", Self.base + "/.well-known/oauth-authorization-server/vci", json: server)
        StubURLProtocol.on("POST", tokenURL, json: [
            "access_token": "AT", "token_type": "DPoP", "expires_in": 300,
        ])
        StubURLProtocol.on("POST", Self.base + "/vci/nonce") { _ in
            let count = StubURLProtocol.requests(to: Self.base + "/vci/nonce").count
            let body = try! JSONSerialization.data(withJSONObject: ["c_nonce": "NONCE-\(count)"])
            return .init(headers: ["Content-Type": "application/json"], body: body)
        }
        StubURLProtocol.on("POST", credentialURL) { _ in
            guard let body = StubURLProtocol.body(of: credentialURL) else { return .init(status: 500) }
            credentialBodies.value.append(body)
            let index = credentialBodies.value.count - 1
            guard Self.ids.indices.contains(index), created.value.indices.contains(index) else {
                return .init(status: 500)
            }
            var options = TestIssuer.Options()
            options.vct = Self.vcts[index]
            options.iat = Self.now
            options.exp = Self.now.addingTimeInterval(3_600)
            options.signWith = issuerScalar
            options.extraHeader = ["x5c": [IssuerX509VerifierTests.leaf]]
            guard let credential = try? issuer.sdJwt(holder: created.value[index].publicJWK, options),
                  let response = try? JSONSerialization.data(withJSONObject: [
                    "credentials": [["credential": credential]],
                  ]) else { return .init(status: 500) }
            return .init(headers: ["Content-Type": "application/json"], body: response)
        }

        var offer = TestIssuer.offerJSON(ids: Self.ids, txCode: false)
        var grants = try #require(offer["grants"] as? [String: Any])
        var grant = try #require(grants[CredentialOfferParser.preAuthorizedGrant] as? [String: Any])
        grant["issuer_state"] = "state-1"
        grant["tx_code"] = ["input_mode": "numeric", "length": 5]
        grants[CredentialOfferParser.preAuthorizedGrant] = grant
        offer["grants"] = grants
        let offerData = try JSONSerialization.data(withJSONObject: offer)
        let encoded = try #require(String(decoding: offerData, as: UTF8.self)
            .addingPercentEncoding(withAllowedCharacters: .alphanumerics))
        let link = "\(scheme)://credential_offer?credential_offer=\(encoded)"

        let client = OpenID4VCIClient(
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]), store: store,
            makeKey: { tag in
                let signer = TestSigner(tag: tag, key: P256.Signing.PrivateKey())
                created.value.append(signer)
                return signer
            },
            deleteKey: { deleted.value.append($0) },
            now: { fixedNow }, languages: { ["en"] },
            keyAttestationProvider: MultiKeyAttestationProvider(scalar: scalar, keys: attestedKeys),
            keyAttestationTrustSource: MultiKeyAttestationTrustSource(root: root),
            walletAttestationProvider: MultiWalletAttestationProvider(
                root: root, scalar: scalar, now: Self.now, receivedKey: clientKey),
            issuerCertificateTrustSource: WalletTestIssuerX509TrustSource(
                root: issuerRoot, vcts: Set(Self.vcts)))
        let preview = try await client.preview(offer: link)
        #expect(preview.credentials.map(\.id) == Self.ids)
        let saved = try await client.issueAll(
            preview, selectedConfigurationIds: Array(Self.ids.reversed()), transactionCode: "12345")

        #expect(StubURLProtocol.requests(to: tokenURL).count == 1)
        #expect(StubURLProtocol.requests(to: Self.base + "/vci/nonce").count == 2)
        #expect(StubURLProtocol.requests(to: credentialURL).count == 2)
        #expect(credentialBodies.value.count == 2)
        #expect(saved.map(\.credentialConfigurationId) == Self.ids)
        #expect(saved.map(\.vct) == Self.vcts)
        #expect(store.items == saved)
        #expect(Set(saved.map(\.keyTag)).count == 2)
        #expect(Set(saved.map(\.confirmationCode)).count == 2)
        try #require(created.value.count == 2 && attestedKeys.value.count == 2)
        #expect(deleted.value.isEmpty)

        let tokenRequest = try #require(StubURLProtocol.requests(to: tokenURL).first)
        let tokenBody = String(decoding: try #require(StubURLProtocol.body(of: tokenURL)), as: UTF8.self)
        #expect(tokenBody.contains("pre-authorized_code=PRE-CODE"))
        #expect(tokenBody.contains("tx_code=12345"))
        let dpopText = try #require(tokenRequest.value(forHTTPHeaderField: "DPoP"))
        let dpop = try #require(JWS.parse(dpopText))
        let dpopKey = try #require(clientKey.value)
        let dpopPublic = try #require(dpopKey.cryptoKey)
        #expect((dpop.header["jwk"] as? [String: String]) == dpopKey.proofMembers)
        #expect(JWS.verifyES256(dpop, with: dpopPublic))
        let wiaText = try #require(tokenRequest.value(forHTTPHeaderField: "OAuth-Client-Attestation"))
        let wia = try WalletAttestationVerifier.validate(
            wiaText, clientKey: dpopKey,
            providerIssuer: URL(string: "https://wallet-provider.example.com")!,
            trustedRootDER: [root], now: Self.now)
        let popText = try #require(tokenRequest.value(forHTTPHeaderField: "OAuth-Client-Attestation-PoP"))
        let pop = try #require(JWS.parse(popText))
        #expect(pop.payload["iss"] as? String == wia.clientID)
        #expect(pop.payload["aud"] as? String == Self.base + "/vci")
        #expect(JWS.verifyES256(pop, with: dpopPublic))

        var resourceJTIs: [String] = []
        var attestationJWTs: [String] = []
        for (index, request) in StubURLProtocol.requests(to: credentialURL).enumerated() {
            #expect(request.value(forHTTPHeaderField: "Authorization") == "DPoP AT")
            let resourceText = try #require(request.value(forHTTPHeaderField: "DPoP"))
            let resource = try #require(JWS.parse(resourceText))
            #expect((resource.header["jwk"] as? [String: String]) == dpopKey.proofMembers)
            #expect(JWS.verifyES256(resource, with: dpopPublic))
            #expect(resource.payload["htm"] as? String == "POST")
            #expect(resource.payload["htu"] as? String == credentialURL)
            #expect(resource.payload["ath"] as? String ==
                    Base64URL.encode(Data(SHA256.hash(data: Data("AT".utf8)))))
            resourceJTIs.append(try #require(resource.payload["jti"] as? String))

            let body = try #require(JSONSerialization.jsonObject(with: credentialBodies.value[index]) as? [String: Any])
            #expect(body["credential_configuration_id"] as? String == Self.ids[index])
            let proofText = try #require(((body["proofs"] as? [String: Any])?["jwt"] as? [String])?.first)
            let proof = try #require(JWS.parse(proofText))
            let signer = created.value[index]
            #expect((proof.header["jwk"] as? [String: String]) == signer.publicJWK.proofMembers)
            #expect(proof.payload["nonce"] as? String == "NONCE-\(index + 1)")
            #expect(JWS.verifyES256(proof, with: signer.key.publicKey))
            #expect(attestedKeys.value[index] == signer.publicJWK)
            let ka = try #require(proof.header["key_attestation"] as? String)
            #expect(try KeyAttestationVerifier.validate(
                ka, holderKey: signer.publicJWK, nonce: "NONCE-\(index + 1)",
                requirements: Self.assurance, trustedRootDER: [root], now: Self.now) == ka)
            attestationJWTs.append(ka)
            #expect(saved[index].keyTag == signer.tag)
            #expect(saved[index].confirmationCode == signer.publicJWK.confirmationCode)
        }
        #expect(Set(resourceJTIs).count == 2)
        #expect(Set(attestationJWTs).count == 2)
    }
}
}

nonisolated private struct MultiKeyAttestationProvider: KeyAttestationProvider {
    let scalar: Data
    let keys: Box<[PublicJWK]>

    func supports(issuer: URL) -> Bool { issuer.absoluteString == TestIssuer.base }

    func attestation(for holderKey: PublicJWK, nonce: String?, issuer: URL) async throws -> String {
        guard supports(issuer: issuer), let nonce, nonce.hasPrefix("NONCE-") else {
            throw WalletError.unsupportedKeyAttestation
        }
        keys.value.append(holderKey)
        let signer = try P256.Signing.PrivateKey(rawRepresentation: scalar)
        return try JWS.make(
            header: ["typ": "key-attestation+jwt", "alg": "ES256", "x5c": [KeyAttestationVerifierTests.leaf]],
            payload: [
                "iat": 1_794_182_390, "exp": 1_794_186_000,
                "nonce": nonce,
                "attested_keys": [holderKey.proofMembers],
                "key_storage": ["iso_18045_high"],
                "user_authentication": ["iso_18045_high"],
            ]) { try signer.signature(for: $0).rawRepresentation }
    }
}

nonisolated private struct MultiKeyAttestationTrustSource: KeyAttestationTrustSource {
    let root: Data

    func trustedRoots(for attestation: String, issuer: URL) async throws -> [Data] {
        guard issuer.absoluteString == TestIssuer.base else { throw WalletError.unsupportedKeyAttestation }
        return [root]
    }
}

nonisolated private struct MultiWalletAttestationProvider: WalletAttestationProvider {
    let root: Data
    let scalar: Data
    let now: Date
    let receivedKey: Box<PublicJWK?>

    func supports(issuer: URL) -> Bool { issuer.absoluteString == TestIssuer.base }

    func attestation(for clientKey: PublicJWK, issuer: URL) async throws -> WalletClientAttestation {
        guard supports(issuer: issuer) else { throw WalletError.unsupportedKeyAttestation }
        receivedKey.value = clientKey
        let signer = try P256.Signing.PrivateKey(rawRepresentation: scalar)
        let jwt = try JWS.make(
            header: ["typ": "oauth-client-attestation+jwt", "alg": "ES256", "x5c": [KeyAttestationVerifierTests.leaf]],
            payload: [
                "iss": "https://wallet-provider.example.com", "sub": "wallet.example",
                "iat": 1_794_182_390, "nbf": 1_794_182_390, "exp": 1_794_186_000,
                "cnf": ["jwk": clientKey.proofMembers],
            ]) { try signer.signature(for: $0).rawRepresentation }
        return try WalletAttestationVerifier.validate(
            jwt, clientKey: clientKey,
            providerIssuer: URL(string: "https://wallet-provider.example.com")!,
            trustedRootDER: [root], now: now)
    }
}

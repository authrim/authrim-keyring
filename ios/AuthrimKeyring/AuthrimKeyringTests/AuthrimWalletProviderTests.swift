import CryptoKit
import DeviceCheck
import Foundation
import Testing
@testable import AuthrimKeyring

nonisolated private final class FakeAppAttest: AppAttestService, @unchecked Sendable {
    private let lock = NSLock()
    private var _events: [String] = []
    private var _hashes: [Data] = []
    var supported = true
    var failAssertions = false
    var attestError: Error?
    var isSupported: Bool { supported }
    var events: [String] { lock.lock(); defer { lock.unlock() }; return _events }
    var hashes: [Data] { lock.lock(); defer { lock.unlock() }; return _hashes }
    private func log(_ event: String) { lock.lock(); _events.append(event); lock.unlock() }
    func generateKey() async throws -> String { log("generateKey"); return "KEY-\(events.count)" }
    func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data {
        log("attestKey")
        lock.lock(); _hashes.append(clientDataHash); lock.unlock()
        if let attestError { throw attestError }
        return Data("attestation".utf8)
    }
    func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data {
        log("assertion")
        if failAssertions { throw WalletError.keyUnavailable("gone") }
        lock.lock(); _hashes.append(clientDataHash); lock.unlock()
        return Data("assertion".utf8)
    }
}

nonisolated private final class MemoryAppAttestState: AppAttestStateStore, @unchecked Sendable {
    private let lock = NSLock()
    private var value: AppAttestState?
    func load() -> AppAttestState? { lock.lock(); defer { lock.unlock() }; return value }
    func save(_ state: AppAttestState) throws { lock.lock(); value = state; lock.unlock() }
    func clear() { lock.lock(); value = nil; lock.unlock() }
}

extension StubbedNetworkTests {
@Suite(.serialized)
struct AuthrimWalletProviderTests {
    static let origin = URL(string: "https://provider.example.net")!
    static let issuerID = TestIssuer.base
    static let providerIssuer = URL(string: "https://provider.example.net")!

    init() { StubURLProtocol.reset() }

    private struct Setup {
        let provider: AuthrimWalletProvider
        let appAttest: FakeAppAttest
        let state: MemoryAppAttestState
        let calls: Box<[String]>
    }

    private func jwtRoot() throws -> Data { try #require(Data(base64Encoded: AuthrimPKIFixture.root)) }

    private func walletJWT(cnf: PublicJWK, sub: String = "keyring-ios", iat: Int? = nil, life: Int = 3_605, omitIat: Bool = false) throws -> String {
        let scalar = try #require(Data(base64Encoded: AuthrimPKIFixture.leafScalar))
        let key = try P256.Signing.PrivateKey(rawRepresentation: scalar)
        let now = Int(Date().timeIntervalSince1970)
        return try JWS.make(
            header: ["alg": "ES256", "typ": "oauth-client-attestation+jwt",
                     "x5c": [AuthrimPKIFixture.leaf, AuthrimPKIFixture.issuingCA]],
            payload: ["iss": Self.providerIssuer.absoluteString, "sub": sub, "exp": now - 5 + life,
                      "cnf": ["jwk": cnf.proofMembers]].merging(omitIat ? [:] : ["iat": iat ?? now - 5]) { _, new in new }) { try key.signature(for: $0).rawRepresentation }
    }

    private func keyJWT(for holder: PublicJWK, nonce: String, withEKU: Bool = false) throws -> String {
        let scalar = try #require(Data(base64Encoded: withEKU ? KeyAttestationVerifierTests.scalar : AuthrimPKIFixture.leafScalar))
        let key = try P256.Signing.PrivateKey(rawRepresentation: scalar)
        let now = Int(Date().timeIntervalSince1970)
        let chain = withEKU ? [KeyAttestationVerifierTests.leaf] : [AuthrimPKIFixture.leaf, AuthrimPKIFixture.issuingCA]
        return try JWS.make(
            header: ["alg": "ES256", "typ": "key-attestation+jwt", "x5c": chain],
            payload: ["iat": now - 5, "exp": now + 600, "nonce": nonce, "attested_keys": [holder.proofMembers],
                      "key_storage": ["iso_18045_high"]]) { try key.signature(for: $0).rawRepresentation }
    }

    /// A provider service that keeps the contract: challenge, register, attest.
    private func serve(
        registerStatus: Int = 200, unknownKeyOnce: Bool = false, sub: String = "keyring-ios",
        wrongCnf: Bool = false, walletIat: Int? = nil, walletLife: Int = 3_605, omitIat: Bool = false, keyWithEKU: Bool = false,
        challengeText: String? = nil
    ) -> Box<[String]> {
        let calls = Box<[String]>([])
        let base = Self.origin.absoluteString
        let unknown = Box(unknownKeyOnce)
        let counter = Box(0)
        StubURLProtocol.on("POST", base + "/challenge") { _ in
            counter.value += 1
            calls.value.append("challenge")
            let body = try! JSONSerialization.data(withJSONObject: ["challenge": challengeText ?? "CHALLENGE-\(counter.value)-0123456789"])
            return .init(headers: ["Content-Type": "application/json"], body: body)
        }
        StubURLProtocol.on("POST", base + "/register") { _ in
            calls.value.append("register")
            return .init(status: registerStatus, headers: ["Content-Type": "application/json"], body: Data("{}".utf8))
        }
        for purpose in ["wallet-attestation", "key-attestation"] {
            StubURLProtocol.on("POST", base + "/" + purpose) { _ in
                calls.value.append(purpose)
                if unknown.value {
                    unknown.value = false
                    return .init(status: 401, headers: ["Content-Type": "application/json"],
                                 body: Data(#"{"error":"unknown_key"}"#.utf8))
                }
                guard let data = StubURLProtocol.body(of: base + "/" + purpose),
                      let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let members = object["jwk"] as? [String: Any], let jwk = PublicJWK(from: members)
                else { return .init(status: 400) }
                let cnf = wrongCnf ? PublicJWK(x963: P256.Signing.PrivateKey().publicKey.x963Representation)! : jwk
                let jwt = purpose == "wallet-attestation"
                    ? try? self.walletJWT(cnf: cnf, sub: sub, iat: walletIat, life: walletLife, omitIat: omitIat)
                    : try? self.keyJWT(for: jwk, nonce: object["nonce"] as? String ?? "", withEKU: keyWithEKU)
                guard let jwt, let body = try? JSONSerialization.data(withJSONObject: ["attestation": jwt])
                else { return .init(status: 500) }
                return .init(headers: ["Content-Type": "application/json"], body: body)
            }
        }
        return calls
    }

    private func setup(
        roots: [Data]? = nil, issuers: Set<String> = [AuthrimWalletProviderTests.issuerID]
    ) throws -> Setup {
        let appAttest = FakeAppAttest()
        let state = MemoryAppAttestState()
        let provider = AuthrimWalletProvider(
            origin: Self.origin, issuer: Self.providerIssuer, roots: try roots ?? [try jwtRoot()],
            clientID: "keyring-ios", issuers: issuers, appAttest: appAttest, state: state,
            http: WalletHTTP(protocolClasses: [StubURLProtocol.self]))
        return Setup(provider: provider, appAttest: appAttest, state: state, calls: Box([]))
    }

    private var issuerURL: URL { URL(string: Self.issuerID)! }
    private func newKey() -> PublicJWK { PublicJWK(x963: P256.Signing.PrivateKey().publicKey.x963Representation)! }

    @Test func registersOnceThenIssuesAWalletAttestationBoundToTheKey() async throws {
        let calls = serve()
        let s = try setup()
        let key = newKey()
        let result = try await s.provider.attestation(for: key, issuer: issuerURL)
        #expect(result.clientID == "keyring-ios")
        #expect(calls.value == ["challenge", "register", "challenge", "wallet-attestation"])
        #expect(s.state.load() == AppAttestState(keyID: "KEY-1", registered: true))
        // The assertion covers provider, purpose, the one-time challenge and the key's thumbprint.
        let expected = "authrim-wallet-provider/v1\nwallet-attestation\nCHALLENGE-2-0123456789\n"
            + Base64URL.encode(key.thumbprint)
        #expect(s.appAttest.hashes.last == Data(SHA256.hash(data: Data(expected.utf8))))
        #expect(s.appAttest.hashes.first == Data(SHA256.hash(data: Data("CHALLENGE-1-0123456789".utf8))))
        _ = try await s.provider.attestation(for: newKey(), issuer: issuerURL)
        #expect(s.appAttest.events.filter { $0 == "attestKey" }.count == 1)
    }

    @Test func keyAttestationCoversTheIssuersNonceAndValidatesAgainstPinnedRoots() async throws {
        _ = serve()
        let s = try setup()
        let holder = newKey()
        let jwt = try await s.provider.attestation(for: holder, nonce: "NONCE-1", issuer: issuerURL)
        let expected = "authrim-wallet-provider/v1\nkey-attestation\nCHALLENGE-2-0123456789\n"
            + Base64URL.encode(holder.thumbprint) + "\nNONCE-1"
        #expect(s.appAttest.hashes.last == Data(SHA256.hash(data: Data(expected.utf8))))
        let trust = PinnedKeyAttestationTrust(roots: [try jwtRoot()], issuers: [Self.issuerID])
        let roots = try await trust.trustedRoots(for: jwt, issuer: issuerURL)
        _ = try KeyAttestationVerifier.validate(
            jwt, holderKey: holder, nonce: "NONCE-1",
            requirements: .init(acceptedKeyStorage: ["iso_18045_high"], acceptedUserAuthentication: []),
            trustedRootDER: roots, now: Date())
        await #expect(throws: WalletError.unsupportedKeyAttestation) {
            _ = try await trust.trustedRoots(for: jwt, issuer: URL(string: "https://other.example.com")!)
        }
        await #expect(throws: WalletError.unsupportedKeyAttestation) {
            _ = try await s.provider.attestation(for: holder, nonce: nil, issuer: issuerURL)
        }
    }

    @Test func attestsOnlyForListedIssuersAndSupportedDevices() throws {
        _ = serve()
        let s = try setup()
        #expect(s.provider.supports(issuer: issuerURL))
        #expect(!s.provider.supports(issuer: URL(string: "https://issuer.eudiw.dev")!))
        s.appAttest.supported = false
        #expect(!s.provider.supports(issuer: issuerURL))
        #expect(!(try setup(roots: []).provider.supports(issuer: issuerURL)))
    }

    @Test func registersAgainWhenTheProviderDoesNotKnowTheKey() async throws {
        let calls = serve(unknownKeyOnce: true)
        let s = try setup()
        _ = try await s.provider.attestation(for: newKey(), issuer: issuerURL)
        #expect(calls.value.filter { $0 == "register" }.count == 2)
        #expect(calls.value.last == "wallet-attestation")
    }

    @Test func registersAgainWhenAppAttestLostTheKey() async throws {
        let calls = serve()
        let s = try setup()
        _ = try await s.provider.attestation(for: newKey(), issuer: issuerURL)
        s.appAttest.failAssertions = true
        await #expect(throws: WalletError.self) { _ = try await s.provider.attestation(for: self.newKey(), issuer: self.issuerURL) }
        #expect(s.state.load() == nil)
        // The key is registered again once; if that one fails too, the request fails and no state is kept.
        #expect(calls.value.filter { $0 == "register" }.count == 2)
    }

    @Test func refusesWhatDoesNotValidate() async throws {
        for variant in 0..<3 {
            StubURLProtocol.reset()
            _ = serve(sub: variant == 1 ? "other-client" : "keyring-ios", wrongCnf: variant == 0)
            let other = try #require(Data(base64Encoded: IssuerX509VerifierTests.root))
            let s = try setup(roots: variant == 2 ? [other] : nil)
            await #expect(throws: WalletError.self, Comment(rawValue: "variant \(variant)")) {
                _ = try await s.provider.attestation(for: self.newKey(), issuer: self.issuerURL)
            }
        }
    }

    @Test func rejectedRegistrationLeavesNoState() async throws {
        _ = serve(registerStatus: 403)
        let s = try setup()
        await #expect(throws: WalletError.self) { _ = try await s.provider.attestation(for: self.newKey(), issuer: self.issuerURL) }
        #expect(s.state.load() == nil)
    }

    @Test func refusesAnswersThatBreakTheContract() async throws {
        let cases: [(String, () -> Void, Bool)] = [
            ("no iat", { _ = self.serve(omitIat: true) }, true),
            ("longer than 24 h", { _ = self.serve(walletLife: 90_000) }, true),
            ("key attestation chain with an extended key usage", { _ = self.serve(keyWithEKU: true) }, false),
        ]
        for (name, arrange, wallet) in cases {
            StubURLProtocol.reset()
            arrange()
            let s = try setup()
            await #expect(throws: WalletError.self, Comment(rawValue: name)) {
                if wallet { _ = try await s.provider.attestation(for: self.newKey(), issuer: self.issuerURL) }
                else { _ = try await s.provider.attestation(for: self.newKey(), nonce: "NONCE-1", issuer: self.issuerURL) }
            }
        }
    }

    @Test func concurrentRequestsRegisterOnceAndKeepTheirOrder() async throws {
        let calls = serve()
        let s = try setup()
        async let first = s.provider.attestation(for: newKey(), issuer: issuerURL)
        async let second = s.provider.attestation(for: newKey(), nonce: "NONCE-2", issuer: issuerURL)
        async let third = s.provider.attestation(for: newKey(), issuer: issuerURL)
        _ = try await (first, second, third)
        #expect(calls.value.filter { $0 == "register" }.count == 1)
        #expect(s.appAttest.events.filter { $0 == "generateKey" }.count == 1)
        // The registration's challenge, then a challenge and an answer for each of the three requests,
        // and each request's two calls are adjacent (no other request's challenge in between).
        let order = calls.value
        #expect(order.count == 8)
        let pairs = order.dropFirst(2).enumerated().filter { $0.offset % 2 == 0 }.map { $0.element }
        #expect(pairs == ["challenge", "challenge", "challenge"])
    }

    @Test func retriesTheSameKeyAfterAppleServersWereUnavailable() async throws {
        let calls = serve()
        let s = try setup()
        s.appAttest.attestError = DCError(.serverUnavailable)
        await #expect(throws: WalletError.self) { _ = try await s.provider.attestation(for: self.newKey(), issuer: self.issuerURL) }
        let pending = try #require(s.state.load())
        #expect(pending.keyID == "KEY-1" && !pending.registered && pending.challenge != nil)
        s.appAttest.attestError = nil
        _ = try await s.provider.attestation(for: newKey(), issuer: issuerURL)
        #expect(s.appAttest.events.filter { $0 == "generateKey" }.count == 1)
        #expect(calls.value.filter { $0 == "register" }.count == 1)
        #expect(s.state.load() == AppAttestState(keyID: "KEY-1", registered: true))
        // Apple is asked again with the same key and the same client data hash.
        let attests = s.appAttest.hashes.prefix(2)
        #expect(attests.count == 2 && attests.first == attests.last)
        // Any other failure of the attestation drops the key.
        let t = try setup()
        t.appAttest.attestError = DCError(.invalidInput)
        await #expect(throws: WalletError.self) { _ = try await t.provider.attestation(for: self.newKey(), issuer: self.issuerURL) }
        #expect(t.state.load() == nil)
    }

    @Test func resumesWithTheSavedAttestationAfterATransportFailure() async throws {
        let calls = serve()
        let s = try setup()
        StubURLProtocol.on("POST", Self.origin.absoluteString + "/register") { _ in .init(failWith: .notConnectedToInternet) }
        await #expect(throws: (any Error).self) { _ = try await s.provider.attestation(for: self.newKey(), issuer: self.issuerURL) }
        let saved = try #require(s.state.load())
        #expect(!saved.registered && saved.attestation != nil)
        _ = serve()
        _ = try await s.provider.attestation(for: newKey(), issuer: issuerURL)
        #expect(s.appAttest.events.filter { $0 == "attestKey" }.count == 1)
        #expect(s.appAttest.events.filter { $0 == "generateKey" }.count == 1)
        _ = calls
    }

    @Test func aBusyProviderKeepsTheSavedAttestationButARefusalDropsTheKey() async throws {
        _ = serve()
        for (status, keeps) in [(503, true), (429, true), (403, false), (400, false)] {
            StubURLProtocol.reset()
            _ = serve(registerStatus: status)
            let s = try setup()
            await #expect(throws: WalletError.self) { _ = try await s.provider.attestation(for: self.newKey(), issuer: self.issuerURL) }
            #expect((s.state.load()?.attestation != nil) == keeps, Comment(rawValue: "status \(status)"))
        }
    }

    @Test func acceptsChallengesWithSpacesAndIssuersWithPaths() async throws {
        _ = serve(challengeText: "challenge with spaces 0123456789")
        let s = try setup()
        _ = try await s.provider.attestation(for: newKey(), issuer: issuerURL)
        let root = AuthrimPKIFixture.root
        let config = try WalletDeploymentConfig(info: [
            "WalletRedirectURI": "https://keyring.example.net/oauth/callback",
            "WalletProviderIssuers": ["https://issuer.example.com/tenant/acme"],
            "WalletProviderPinnedRoots": [root],
        ], allowDebugProvider: false)
        #expect(config.credentialIssuers == ["https://issuer.example.com/tenant/acme"])
        for bad in ["https://issuer.example.com/", "https://issuer.example.com?x=1", "http://issuer.example.com"] {
            #expect(throws: WalletDeploymentConfig.Problem.self, Comment(rawValue: bad)) {
                try WalletDeploymentConfig(info: [
                    "WalletRedirectURI": "https://keyring.example.net/oauth/callback", "WalletProviderIssuers": [bad]],
                    allowDebugProvider: false)
            }
        }
    }

    @Test func factoryFailsClosedAndKeepsDebugOutOfRelease() throws {
        let root = AuthrimPKIFixture.root
        var info: [String: Any] = [
            "WalletRedirectURI": "https://keyring.example.net/oauth/callback",
            "WalletProviderOrigin": "https://provider.example.net", "WalletProviderPinnedRoots": [root],
            "AuthrimTrustedRoots": [root], "WalletProviderIssuers": [TestIssuer.base],
        ]
        let ready = try WalletDeploymentConfig(info: info, allowDebugProvider: true)
        let services = try WalletProviderFactory.make(
            config: ready, isRelease: true, appAttest: FakeAppAttest(), state: MemoryAppAttestState())
        #expect(services != nil)
        info["WalletProviderKind"] = "debugUnattested"
        let debug = try WalletDeploymentConfig(info: info, allowDebugProvider: true)
        #expect(throws: WalletDeploymentConfig.Problem.invalid("WalletProviderKind")) {
            _ = try WalletProviderFactory.make(config: debug, isRelease: true, appAttest: FakeAppAttest())
        }
        info["WalletProviderIssuers"] = []
        let noIssuers = try WalletDeploymentConfig(info: info, allowDebugProvider: true)
        #expect(throws: WalletDeploymentConfig.Problem.missing("WalletProviderIssuers")) {
            _ = try WalletProviderFactory.make(config: noIssuers, isRelease: false, appAttest: FakeAppAttest())
        }
        info.removeValue(forKey: "WalletProviderOrigin")
        let unconfigured = try WalletDeploymentConfig(info: info, allowDebugProvider: true)
        #expect(try WalletProviderFactory.make(config: unconfigured, isRelease: true) == nil)
    }

    @Test func compositesAskTheFirstSupportingProvider() async throws {
        _ = serve()
        let s = try setup()
        let eudi = EUDITestWalletAttestationProvider()
        let composite = CompositeWalletAttestationProvider(providers: [eudi, s.provider])
        #expect(composite.supports(issuer: issuerURL))
        #expect(composite.supports(issuer: URL(string: "https://issuer.eudiw.dev")!))
        #expect(!composite.supports(issuer: URL(string: "https://nobody.example.com")!))
        let result = try await composite.attestation(for: newKey(), issuer: issuerURL)
        #expect(result.clientID == "keyring-ios")
    }
}
}

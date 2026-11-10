import CryptoKit
import Foundation
import Testing
@testable import AuthrimKeyring

/// Separate, throw-away signer and issuer CAs. Fixture keys never become app trust anchors.
nonisolated enum EUDITestLoTEFixture {
    static let now = Date(timeIntervalSince1970: 1_794_182_400)
    static let issuer = URL(string: "https://issuer.eudiw.dev")!
    static let ehic = "urn:eudi:ehic:1"
    static let healthID = "urn:eu.europa.ec.eudi:hiid:1"
    static let issuerRootSHA256 = Data(SHA256.hash(data: Data(base64Encoded: IssuerX509VerifierTests.root)!))

    static let entitlements = EUDITestIssuerEntitlementPolicy(
        issuer: issuer, authorizedRootSHA256ByVCT: [
            ehic: [issuerRootSHA256], healthID: [issuerRootSHA256],
        ])

    static func pins() throws -> EUDITestLoTESignerPins {
        let leaf = try #require(Data(base64Encoded: KeyAttestationVerifierTests.leaf))
        let root = try #require(Data(base64Encoded: KeyAttestationVerifierTests.root))
        return EUDITestLoTESignerPins(
            signerSHA256: Data(SHA256.hash(data: leaf)), rootCertificatesDER: [root],
            minimumSequence: 11)
    }

    static func jwt(
        sequence: Int = 11, issuedAt: Date = now.addingTimeInterval(-3_600),
        nextUpdate: Date = now.addingTimeInterval(4 * 86_400),
        status: String = "http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified",
        version: Int = 1, distributionPoint: String = EUDITestLoTEVerifier.url.absoluteString,
        extraIssuerRoots: [String] = [],
        signer: P256.Signing.PrivateKey? = nil
    ) throws -> String {
        let key = try signer ?? P256.Signing.PrivateKey(
            rawRepresentation: #require(Data(base64Encoded: KeyAttestationVerifierTests.scalar)))
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        let issuerRoot = IssuerX509VerifierTests.root
        let payload: [String: Any] = ["LoTE": [
            "ListAndSchemeInformation": [
                "LoTEVersionIdentifier": version,
                "LoTESequenceNumber": sequence,
                "ListIssueDateTime": formatter.string(from: issuedAt),
                "NextUpdate": formatter.string(from: nextUpdate),
                "LoTEType": "http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList",
                "SchemeTerritory": "EU",
                "DistributionPoints": [distributionPoint],
            ],
            "TrustedEntitiesList": [["TrustedEntityServices": [["ServiceInformation": [
                "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance",
                "ServiceStatus": status,
                "StatusStartingTime": formatter.string(from: issuedAt),
                "ServiceDigitalIdentity": ["X509Certificates":
                    ([issuerRoot] + extraIssuerRoots).map { ["val": $0] }],
            ]]]]],
        ]]
        return try JWS.make(header: [
            "alg": "ES256", "typ": "JOSE+JSON", "iat": Int(issuedAt.timeIntervalSince1970),
            "x5c": [KeyAttestationVerifierTests.leaf],
        ], payload: payload) { try key.signature(for: $0).rawRepresentation }
    }

    static func response(_ jwt: String) -> WalletHTTPResponse {
        WalletHTTPResponse(status: 200, data: Data(jwt.utf8), dpopNonce: nil,
                           wwwAuthenticate: nil, clientAttestationChallenge: nil)
    }
}

nonisolated final class MemoryEUDITestLoTERecordStore: EUDITestLoTERecordStore, @unchecked Sendable {
    var record: EUDITestLoTERecord?
    func load() throws -> EUDITestLoTERecord? { record }
    func save(_ record: EUDITestLoTERecord) throws { self.record = record }
}

nonisolated final class LoTETestBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: T
    init(_ value: T) { stored = value }
    var value: T {
        get { lock.lock(); defer { lock.unlock() }; return stored }
        set { lock.lock(); defer { lock.unlock() }; stored = newValue }
    }
}

actor LoTERefreshBarrier {
    private var suspended = false
    private var entered: CheckedContinuation<Void, Never>?
    private var releaseContinuation: CheckedContinuation<Void, Never>?

    func suspend() async {
        suspended = true
        entered?.resume()
        entered = nil
        await withCheckedContinuation { releaseContinuation = $0 }
    }

    func waitUntilSuspended() async {
        if suspended { return }
        await withCheckedContinuation { entered = $0 }
    }

    func release() {
        releaseContinuation?.resume()
        releaseContinuation = nil
    }
}

@Suite
struct EUDITestLoTETests {
    @Test func verifiesPinnedSignerAndExtractsOnlyActiveIssuanceRoots() throws {
        let token = try EUDITestLoTEFixture.jwt()
        let snapshot = try EUDITestLoTEVerifier.verify(
            token, pins: EUDITestLoTEFixture.pins(), now: EUDITestLoTEFixture.now)
        #expect(snapshot.sequence == 11)
        #expect(snapshot.issuanceRootsDER == [try #require(Data(base64Encoded: IssuerX509VerifierTests.root))])
        let revoked = try EUDITestLoTEFixture.jwt(status: "http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/withdrawn")
        #expect(throws: WalletError.self) {
            try EUDITestLoTEVerifier.verify(revoked, pins: EUDITestLoTEFixture.pins(), now: EUDITestLoTEFixture.now)
        }
    }

    @Test func rejectsTamperingAnotherSignerAndExpiredCertificate() throws {
        let token = try EUDITestLoTEFixture.jwt()
        let parts = token.split(separator: ".").map(String.init)
        let payload = try #require(Base64URL.decode(parts[1]))
        var object = try #require(JSONSerialization.jsonObject(with: payload) as? [String: Any])
        var lote = try #require(object["LoTE"] as? [String: Any])
        var info = try #require(lote["ListAndSchemeInformation"] as? [String: Any])
        info["LoTESequenceNumber"] = 99
        lote["ListAndSchemeInformation"] = info
        object["LoTE"] = lote
        let changed = Base64URL.encode(try JSONSerialization.data(withJSONObject: object))
        let tampered = parts[0] + "." + changed + "." + parts[2]
        #expect(throws: WalletError.self) {
            try EUDITestLoTEVerifier.verify(tampered, pins: EUDITestLoTEFixture.pins(), now: EUDITestLoTEFixture.now)
        }
        let otherKey = try EUDITestLoTEFixture.jwt(signer: P256.Signing.PrivateKey())
        #expect(throws: WalletError.self) {
            try EUDITestLoTEVerifier.verify(otherKey, pins: EUDITestLoTEFixture.pins(), now: EUDITestLoTEFixture.now)
        }
        let wrongPins = EUDITestLoTESignerPins(
            signerSHA256: Data(repeating: 0, count: 32),
            rootCertificatesDER: try EUDITestLoTEFixture.pins().rootCertificatesDER,
            minimumSequence: 11)
        #expect(throws: WalletError.self) {
            try EUDITestLoTEVerifier.verify(token, pins: wrongPins, now: EUDITestLoTEFixture.now)
        }
        let later = Date(timeIntervalSince1970: 2_200_000_000)
        let laterToken = try EUDITestLoTEFixture.jwt(
            issuedAt: later.addingTimeInterval(-3_600), nextUpdate: later.addingTimeInterval(86_400))
        #expect(throws: WalletError.self) {
            try EUDITestLoTEVerifier.verify(laterToken, pins: EUDITestLoTEFixture.pins(), now: later)
        }
    }

    @Test func rejectsOtherListIdentityAndExpiredUpdate() async throws {
        let pins = try EUDITestLoTEFixture.pins()
        for token in [
            try EUDITestLoTEFixture.jwt(sequence: 10),
            try EUDITestLoTEFixture.jwt(version: 2),
            try EUDITestLoTEFixture.jwt(distributionPoint: "https://example.com/other.jwt"),
        ] {
            #expect(throws: WalletError.self) {
                try EUDITestLoTEVerifier.verify(token, pins: pins, now: EUDITestLoTEFixture.now)
            }
        }
        let expired = try EUDITestLoTEFixture.jwt(nextUpdate: EUDITestLoTEFixture.now.addingTimeInterval(-1))
        let cache = EUDITestLoTECache(
            http: WalletHTTP(testResponse: { _ in EUDITestLoTEFixture.response(expired) }),
            pins: pins, recordStore: MemoryEUDITestLoTERecordStore(),
            now: { EUDITestLoTEFixture.now })
        await #expect(throws: WalletError.self) { try await cache.snapshot() }
    }

    @Test func refusesAnUnpinnedLiveListBeforeNetworkOrCode() async throws {
        let calls = LoTETestBox(0)
        let http = WalletHTTP(testResponse: { _ in
            calls.value += 1
            return EUDITestLoTEFixture.response(try EUDITestLoTEFixture.jwt())
        })
        let source = EUDITestIssuerCertificateTrustSource(
            http: http, entitlementPolicy: EUDITestLoTEFixture.entitlements,
            recordStore: MemoryEUDITestLoTERecordStore(), now: { EUDITestLoTEFixture.now })
        await #expect(throws: WalletError.unsupportedIssuerCertificateTrust) {
            try await source.prepare(issuer: EUDITestLoTEFixture.issuer, vct: EUDITestLoTEFixture.ehic)
        }
        #expect(calls.value == 0)
    }

    @Test func refusesIssuerScopeWithoutIndependentEntitlement() async throws {
        let calls = LoTETestBox(0)
        let source = EUDITestIssuerCertificateTrustSource(
            http: WalletHTTP(testResponse: { _ in
                calls.value += 1
                return EUDITestLoTEFixture.response(try EUDITestLoTEFixture.jwt())
            }), pins: try EUDITestLoTEFixture.pins(),
            recordStore: MemoryEUDITestLoTERecordStore(), now: { EUDITestLoTEFixture.now })
        await #expect(throws: WalletError.unsupportedIssuerCertificateTrust) {
            try await source.prepare(issuer: EUDITestLoTEFixture.issuer, vct: EUDITestLoTEFixture.ehic)
        }
        #expect(calls.value == 0)
        let narrowed = EUDITestIssuerCertificateTrustSource(
            http: WalletHTTP(testResponse: { _ in
                calls.value += 1
                return EUDITestLoTEFixture.response(try EUDITestLoTEFixture.jwt())
            }), pins: try EUDITestLoTEFixture.pins(),
            entitlementPolicy: EUDITestIssuerEntitlementPolicy(
                issuer: EUDITestLoTEFixture.issuer,
                authorizedRootSHA256ByVCT: [
                    EUDITestLoTEFixture.ehic: [EUDITestLoTEFixture.issuerRootSHA256],
                ]),
            recordStore: MemoryEUDITestLoTERecordStore(), now: { EUDITestLoTEFixture.now })
        await #expect(throws: WalletError.unsupportedIssuerCertificateTrust) {
            try await narrowed.prepare(issuer: EUDITestLoTEFixture.issuer, vct: EUDITestLoTEFixture.healthID)
        }
        #expect(calls.value == 0)
        let wrongRoot = EUDITestIssuerCertificateTrustSource(
            http: WalletHTTP(testResponse: { _ in
                calls.value += 1
                return EUDITestLoTEFixture.response(try EUDITestLoTEFixture.jwt())
            }), pins: try EUDITestLoTEFixture.pins(),
            entitlementPolicy: EUDITestIssuerEntitlementPolicy(
                issuer: EUDITestLoTEFixture.issuer,
                authorizedRootSHA256ByVCT: [
                    EUDITestLoTEFixture.ehic: [Data(repeating: 0, count: 32)],
                ]),
            recordStore: MemoryEUDITestLoTERecordStore(), now: { EUDITestLoTEFixture.now })
        await #expect(throws: WalletError.self) {
            try await wrongRoot.prepare(issuer: EUDITestLoTEFixture.issuer, vct: EUDITestLoTEFixture.ehic)
        }
        #expect(calls.value == 1)
    }

    @Test func rejectsOtherIssuerAndVCTBeforeFetchingList() async throws {
        let calls = LoTETestBox(0)
        let source = EUDITestIssuerCertificateTrustSource(
            http: WalletHTTP(testResponse: { _ in
                calls.value += 1
                return EUDITestLoTEFixture.response(try EUDITestLoTEFixture.jwt())
            }),
            pins: try EUDITestLoTEFixture.pins(), entitlementPolicy: EUDITestLoTEFixture.entitlements,
            recordStore: MemoryEUDITestLoTERecordStore(),
            now: { EUDITestLoTEFixture.now })
        await #expect(throws: WalletError.self) {
            try await source.prepare(issuer: URL(string: "https://other.eudiw.dev")!, vct: EUDITestLoTEFixture.ehic)
        }
        await #expect(throws: WalletError.self) {
            try await source.prepare(issuer: EUDITestLoTEFixture.issuer, vct: "urn:eudi:pid:1")
        }
        #expect(calls.value == 0)
    }

    @Test func rejectsRolledBackAndInvalidUpdates() async throws {
        let first = try EUDITestLoTEFixture.jwt(sequence: 12)
        let response = LoTETestBox<String?>(first)
        let time = LoTETestBox(EUDITestLoTEFixture.now)
        let store = MemoryEUDITestLoTERecordStore()
        let cache = EUDITestLoTECache(
            http: WalletHTTP(testResponse: { _ in EUDITestLoTEFixture.response(response.value!) }),
            pins: try EUDITestLoTEFixture.pins(), recordStore: store, now: { time.value })
        #expect(try await cache.snapshot().sequence == 12)
        time.value = time.value.addingTimeInterval(25 * 3_600)
        response.value = try EUDITestLoTEFixture.jwt(sequence: 11)
        await #expect(throws: WalletError.self) { try await cache.snapshot() }
        #expect(store.record?.sequence == 12)

        let parts = first.split(separator: ".").map(String.init)
        response.value = parts[0] + "." + parts[1] + "." + Base64URL.encode(Data(repeating: 0, count: 64))
        await #expect(throws: WalletError.self) { try await cache.snapshot() }
        #expect(store.record?.sequence == 12)

        let invalidStatus = LoTETestBox(302)
        let redirectCache = EUDITestLoTECache(
            http: WalletHTTP(testResponse: { _ in
                WalletHTTPResponse(status: invalidStatus.value, data: Data(), dpopNonce: nil,
                                   wwwAuthenticate: nil, clientAttestationChallenge: nil)
            }), pins: try EUDITestLoTEFixture.pins(), recordStore: store,
            now: { time.value })
        await #expect(throws: WalletError.self) { try await redirectCache.snapshot() }
    }

    @Test func acceptsNewerListAndReloadsOnlyVerifiedRecord() async throws {
        let response = LoTETestBox(try EUDITestLoTEFixture.jwt(sequence: 11))
        let time = LoTETestBox(EUDITestLoTEFixture.now)
        let store = MemoryEUDITestLoTERecordStore()
        let pins = try EUDITestLoTEFixture.pins()
        let cache = EUDITestLoTECache(
            http: WalletHTTP(testResponse: { _ in EUDITestLoTEFixture.response(response.value) }),
            pins: pins, recordStore: store, now: { time.value })
        #expect(try await cache.snapshot().sequence == 11)
        time.value = time.value.addingTimeInterval(25 * 3_600)
        response.value = try EUDITestLoTEFixture.jwt(
            sequence: 12, issuedAt: time.value.addingTimeInterval(-3_600),
            nextUpdate: time.value.addingTimeInterval(4 * 86_400))
        #expect(try await cache.snapshot().sequence == 12)
        #expect(store.record?.sequence == 12)
        let reopened = EUDITestLoTECache(
            http: WalletHTTP(testResponse: { _ in throw URLError(.notConnectedToInternet) }),
            pins: pins, recordStore: store, now: { time.value })
        #expect(try await reopened.snapshot().sequence == 12)
    }

    @Test func failedConcurrentRefreshUsesNewestVerifiedList() async throws {
        let calls = LoTETestBox(0)
        let time = LoTETestBox(EUDITestLoTEFixture.now)
        let barrier = LoTERefreshBarrier()
        let first = try EUDITestLoTEFixture.jwt(sequence: 11)
        let next = try EUDITestLoTEFixture.jwt(
            sequence: 12, issuedAt: EUDITestLoTEFixture.now.addingTimeInterval(24 * 3_600),
            nextUpdate: EUDITestLoTEFixture.now.addingTimeInterval(6 * 86_400))
        let cache = EUDITestLoTECache(
            http: WalletHTTP(testResponse: { _ in
                calls.value += 1
                switch calls.value {
                case 1: return EUDITestLoTEFixture.response(first)
                case 2:
                    await barrier.suspend()
                    throw URLError(.notConnectedToInternet)
                default: return EUDITestLoTEFixture.response(next)
                }
            }), pins: try EUDITestLoTEFixture.pins(),
            recordStore: MemoryEUDITestLoTERecordStore(), now: { time.value })
        #expect(try await cache.snapshot().sequence == 11)
        time.value = time.value.addingTimeInterval(25 * 3_600)
        let delayed = Task { try await cache.snapshot() }
        await barrier.waitUntilSuspended()
        #expect(try await cache.snapshot().sequence == 12)
        await barrier.release()
        #expect(try await delayed.value.sequence == 12)
    }

    @Test func networkFailureUsesOnlyAnUnexpiredVerifiedList() async throws {
        let token = try EUDITestLoTEFixture.jwt()
        let response = LoTETestBox<String?>(token)
        let time = LoTETestBox(EUDITestLoTEFixture.now)
        let store = MemoryEUDITestLoTERecordStore()
        let cache = EUDITestLoTECache(
            http: WalletHTTP(testResponse: { _ in
                guard let token = response.value else { throw URLError(.notConnectedToInternet) }
                return EUDITestLoTEFixture.response(token)
            }),
            pins: try EUDITestLoTEFixture.pins(), recordStore: store, now: { time.value })
        #expect(try await cache.snapshot().sequence == 11)
        response.value = nil
        time.value = time.value.addingTimeInterval(25 * 3_600)
        #expect(try await cache.snapshot().sequence == 11)
        time.value = EUDITestLoTEFixture.now.addingTimeInterval(5 * 86_400)
        await #expect(throws: URLError.self) { try await cache.snapshot() }
    }

    @Test func listedRootStillRejectsForgedCredentialSignature() async throws {
        let token = try EUDITestLoTEFixture.jwt(extraIssuerRoots: [KeyAttestationVerifierTests.root])
        let source = EUDITestIssuerCertificateTrustSource(
            http: WalletHTTP(testResponse: { _ in EUDITestLoTEFixture.response(token) }),
            pins: try EUDITestLoTEFixture.pins(), entitlementPolicy: EUDITestLoTEFixture.entitlements,
            recordStore: MemoryEUDITestLoTERecordStore(),
            now: { EUDITestLoTEFixture.now })
        try await source.prepare(issuer: EUDITestLoTEFixture.issuer, vct: EUDITestLoTEFixture.healthID)
        let approved = try await source.trustedRoots(
            for: [try #require(Data(base64Encoded: IssuerX509VerifierTests.leaf))],
            issuer: EUDITestLoTEFixture.issuer, vct: EUDITestLoTEFixture.healthID)
        #expect(approved == [try #require(Data(base64Encoded: IssuerX509VerifierTests.root))])
        let validSigner = try P256.Signing.PrivateKey(
            rawRepresentation: #require(Data(base64Encoded: IssuerX509VerifierTests.scalar)))
        let validJWT = try JWS.make(header: [
            "alg": "ES256", "typ": "dc+sd-jwt", "x5c": [IssuerX509VerifierTests.leaf],
        ], payload: ["iss": EUDITestLoTEFixture.issuer.absoluteString, "vct": EUDITestLoTEFixture.healthID]) {
            try validSigner.signature(for: $0).rawRepresentation
        }
        let validCredential = try ParsedSDJWT(validJWT + "~")
        let verifiedKey = try await IssuerX509Verifier.signingKey(
            of: validCredential, issuer: EUDITestLoTEFixture.issuer,
            vct: EUDITestLoTEFixture.healthID, trustSource: source, now: EUDITestLoTEFixture.now)
        #expect(verifiedKey.isSameKey(as: try #require(PublicJWK(x963: validSigner.publicKey.x963Representation))))
        let jwt = try JWS.make(header: [
            "alg": "ES256", "typ": "dc+sd-jwt", "x5c": [IssuerX509VerifierTests.leaf],
        ], payload: ["iss": EUDITestLoTEFixture.issuer.absoluteString, "vct": EUDITestLoTEFixture.healthID]) {
            try P256.Signing.PrivateKey().signature(for: $0).rawRepresentation
        }
        let credential = try ParsedSDJWT(jwt + "~")
        await #expect(throws: WalletError.self) {
            try await IssuerX509Verifier.signingKey(
                of: credential, issuer: EUDITestLoTEFixture.issuer, vct: EUDITestLoTEFixture.healthID,
                trustSource: source, now: EUDITestLoTEFixture.now)
        }
    }
}

extension StubbedNetworkTests {
    @Suite(.serialized)
    struct EUDITestLoTETransportTests {
        init() { StubURLProtocol.reset() }

        @Test func timeoutFallsBackOnlyWhileVerifiedListIsValid() async throws {
            let token = try EUDITestLoTEFixture.jwt()
            let time = LoTETestBox(EUDITestLoTEFixture.now)
            let endpoint = EUDITestLoTEVerifier.url.absoluteString
            StubURLProtocol.on("GET", endpoint) { _ in .init(body: Data(token.utf8)) }
            let cache = EUDITestLoTECache(
                http: WalletHTTP(protocolClasses: [StubURLProtocol.self]),
                pins: try EUDITestLoTEFixture.pins(),
                recordStore: MemoryEUDITestLoTERecordStore(), now: { time.value })
            #expect(try await cache.snapshot().sequence == 11)
            StubURLProtocol.on("GET", endpoint) { _ in .init(failWith: .timedOut) }
            time.value = EUDITestLoTEFixture.now.addingTimeInterval(25 * 3_600)
            #expect(try await cache.snapshot().sequence == 11)
            time.value = EUDITestLoTEFixture.now.addingTimeInterval(5 * 86_400)
            await #expect(throws: WalletError.self) { try await cache.snapshot() }
        }
    }
}

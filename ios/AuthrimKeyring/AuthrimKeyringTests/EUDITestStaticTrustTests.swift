import CryptoKit
import Foundation
import Testing
@testable import AuthrimKeyring

@Suite
struct EUDITestStaticTrustTests {
    private let issuer = URL(string: "https://issuer.eudiw.dev")!
    private let now = Date(timeIntervalSince1970: 1_794_182_400)

    @Test func masterAndCategoryPreferencesAreIndependent() throws {
        let suite = "EUDITestStaticTrustTests.\(UUID().uuidString)"
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        #expect(!EUDITestMode.isEnabled(.pid, defaults: defaults))
        defaults.set(true, forKey: EUDITestMode.enabledKey)
        #expect(EUDITestMode.isEnabled(.pid, defaults: defaults))
        #expect(EUDITestMode.isEnabled(.pubEAA, defaults: defaults))
        defaults.set(false, forKey: EUDITestMode.pubEAAKey)
        #expect(!EUDITestMode.isEnabled(.pubEAA, defaults: defaults))
        #expect(EUDITestMode.isEnabled(.other, defaults: defaults))
        defaults.set(false, forKey: EUDITestMode.enabledKey)
        #expect(!EUDITestMode.isEnabled(.other, defaults: defaults))
    }

    @Test func pinnedReferenceRootsAreScopedToIssuerAndType() throws {
        let policy = EUDITestStaticTrustPolicy(isEnabled: { _ in true })
        let healthRoots = try policy.trustedRoots(issuer: issuer, vct: "urn:eudi:ehic:1", now: now)
        #expect(healthRoots.count == 1)
        #expect(Data(SHA256.hash(data: healthRoots[0])).map { String(format: "%02x", $0) }.joined()
            == "7d8713f9aeaa821244a22e3559e095e5bb84cce6d732840a9d371055a3059178")
        let pidRoots = try policy.trustedRoots(issuer: issuer, vct: "urn:eudi:pid:1", now: now)
        #expect(pidRoots.count == 2)
        #expect(policy.supports(issuer: issuer, vct: "urn:eu.europa.ec.eudi:tax:1"))
        #expect(!policy.supports(issuer: issuer, vct: "urn:eudi:unknown:1"))
        #expect(!policy.supports(issuer: URL(string: "https://other.eudiw.dev")!, vct: "urn:eudi:ehic:1"))
        #expect(throws: WalletError.self) {
            try policy.trustedRoots(issuer: issuer, vct: "urn:eudi:ehic:1",
                                    now: Date(timeIntervalSince1970: 2_200_000_000))
        }
    }

    @Test func categorySwitchesTakeEffectWithoutRebuildingWallet() async throws {
        let enabled = LoTETestBox<Set<EUDITestMode.Category>>([.pid, .pubEAA, .other])
        let calls = LoTETestBox(0)
        let policy = EUDITestStaticTrustPolicy(isEnabled: { enabled.value.contains($0) })
        let source = EUDITestIssuerCertificateTrustSource(
            http: WalletHTTP(testResponse: { _ in
                calls.value += 1
                throw URLError(.notConnectedToInternet)
            }), staticTestPolicy: policy, now: { Date(timeIntervalSince1970: 1_794_182_400) })
        try await source.prepare(issuer: issuer, vct: "urn:eudi:ehic:1")
        try await source.prepare(issuer: issuer, vct: "urn:eudi:pid:1")
        try await source.prepare(issuer: issuer, vct: "urn:eu.europa.ec.eudi:learning:credential:1")
        #expect(calls.value == 0)
        enabled.value = [.pid, .other]
        await #expect(throws: WalletError.unsupportedIssuerCertificateTrust) {
            try await source.prepare(issuer: issuer, vct: "urn:eudi:ehic:1")
        }
        try await source.prepare(issuer: issuer, vct: "urn:eudi:pid:1")
        #expect(calls.value == 0)
    }
}

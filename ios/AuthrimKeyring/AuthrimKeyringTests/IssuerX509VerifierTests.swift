import CryptoKit
import Foundation
import Testing
@testable import AuthrimKeyring

@Suite
struct IssuerX509VerifierTests {
    private static let issuer = URL(string: "https://issuer.eudiw.dev")!
    private static let diplomaVCT = "urn:eu.europa.ec.eudi:diploma:1:1"
    private static let ehicVCT = "urn:eudi:ehic:1"
    private static let healthIDVCT = "urn:eu.europa.ec.eudi:hiid:1"
    private static let now = Date(timeIntervalSince1970: 1_794_182_400)
    /// Throw-away CA and signer with URI SANs for the EUDI and local test issuers, valid 2026–2036.
    nonisolated static let root = "MIIBhjCCASygAwIBAgIUccnjFjzPUvq8NloZis82wbyhL3gwCgYIKoZIzj0EAwIwITEfMB0GA1UEAwwWS2V5cmluZyBJc3N1ZXIgVGVzdCBDQTAeFw0yNjExMDgyMzM1NDFaFw0zNjExMDUyMzM1NDFaMCExHzAdBgNVBAMMFktleXJpbmcgSXNzdWVyIFRlc3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASauIQ+FZmoCmuZiu9eb7iPN9bxKzmWrDjnlx9a2G3egUrC9tb/Cc5Ev4NE6xBFEWSELVYyWjeTCMkJqn4ZV9j0o0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUDDiUOGv+/bOz3lDjyPgHXQxx/GAwCgYIKoZIzj0EAwIDSAAwRQIgdo+MquKOrsSnLoyoPjr0qGet0txQcTgbTHLxSCTjE8gCIQChTdMv0VeL3b4Jb7VRyXRp15FqDZRwU7WP6p+z9nJwcg=="
    static let leaf = "MIIB7DCCAZGgAwIBAgIUKkiQ3vg+SASisfGzaD7iSZpx88IwCgYIKoZIzj0EAwIwITEfMB0GA1UEAwwWS2V5cmluZyBJc3N1ZXIgVGVzdCBDQTAeFw0yNjExMDgyMzM2NDlaFw0zNjExMDUyMzM2NDlaMCUxIzAhBgNVBAMMGktleXJpbmcgSXNzdWVyIFRlc3QgU2lnbmVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVtEnaKEidBzDQyPdLrjK4hDW0MpVgbSV2YkWXDvFI55Ntz2dpzFnB/oYIKoQ7s2jS0Ye0HwBPxYWxsf+A4lQSKOBojCBnzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDA/BgNVHREEODA2hhhodHRwczovL2lzc3Vlci5ldWRpdy5kZXaGGmh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tMB0GA1UdDgQWBBTQehEOqDxKHQuRIcc4A/OPRVeKRjAfBgNVHSMEGDAWgBQMOJQ4a/79s7PeUOPI+AddDHH8YDAKBggqhkjOPQQDAgNJADBGAiEAzwIsRTjIeAGOWjp/b569/tkjsO8qlVjwsOKQhMEqp3YCIQDC/WZAj9TvzTcXnVplwzMpYp96t/THqcBhODK7kiuDWA=="
    static let scalar = "+dvbneYBrBCEie8kgYIH+pkG3iKYFjHhi8XEAwiAvRw="

    private func fixture() throws -> (root: Data, leaf: Data, signer: P256.Signing.PrivateKey) {
        let root = try #require(Data(base64Encoded: Self.root))
        let leaf = try #require(Data(base64Encoded: Self.leaf))
        let scalar = try #require(Data(base64Encoded: Self.scalar))
        return (root, leaf, try P256.Signing.PrivateKey(rawRepresentation: scalar))
    }

    private func credential(
        signer: P256.Signing.PrivateKey, chain: [String],
        vct: String = Self.diplomaVCT, headerChanges: [String: Any] = [:]
    ) throws -> ParsedSDJWT {
        var header: [String: Any] = ["alg": "ES256", "typ": "dc+sd-jwt", "x5c": chain]
        header.merge(headerChanges) { _, new in new }
        let jwt = try JWS.make(header: header, payload: ["iss": Self.issuer.absoluteString, "vct": vct]) {
            try signer.signature(for: $0).rawRepresentation
        }
        return try ParsedSDJWT(jwt + "~")
    }

    @Test func usesTrustedX509LeafToVerifyCredentialSignature() async throws {
        let f = try fixture()
        let parsed = try credential(signer: f.signer, chain: [Self.leaf])
        let source = TestIssuerTrustSource(root: f.root)
        let key = try await IssuerX509Verifier.signingKey(
            of: parsed, issuer: Self.issuer, vct: Self.diplomaVCT,
            trustSource: source, now: Self.now)
        let expected = try #require(PublicJWK(x963: f.signer.publicKey.x963Representation))
        #expect(key.isSameKey(as: expected))
    }

    @Test func rejectsUntrustedAndSelfAnchoredChains() throws {
        let f = try fixture()
        let parsed = try credential(signer: f.signer, chain: [Self.leaf])
        let chain = try IssuerX509Verifier.certificateChain(of: parsed)
        #expect(throws: WalletError.self) {
            try IssuerX509Verifier.validate(parsed, issuer: Self.issuer,
                                            chainDER: chain, trustedRootDER: [], now: Self.now)
        }
        #expect(throws: WalletError.self) {
            try IssuerX509Verifier.validate(parsed, issuer: Self.issuer,
                                            chainDER: [f.leaf, f.root], trustedRootDER: [f.root], now: Self.now)
        }
        #expect(throws: WalletError.self) {
            try IssuerX509Verifier.validate(parsed, issuer: Self.issuer,
                                            chainDER: [f.root], trustedRootDER: [f.root], now: Self.now)
        }
    }

    @Test func rejectsSignatureNotMadeByCertificateKey() throws {
        let f = try fixture()
        let parsed = try credential(signer: P256.Signing.PrivateKey(), chain: [Self.leaf])
        let chain = try IssuerX509Verifier.certificateChain(of: parsed)
        #expect(throws: WalletError.self) {
            try IssuerX509Verifier.validate(parsed, issuer: Self.issuer,
                                            chainDER: chain, trustedRootDER: [f.root], now: Self.now)
        }
    }

    @Test func rejectsTrustedCertificateForAnotherIssuer() throws {
        let f = try fixture()
        let parsed = try credential(signer: f.signer, chain: [Self.leaf])
        let chain = try IssuerX509Verifier.certificateChain(of: parsed)
        #expect(throws: WalletError.self) {
            try IssuerX509Verifier.validate(
                parsed, issuer: URL(string: "https://other.eudiw.dev")!,
                chainDER: chain, trustedRootDER: [f.root], now: Self.now)
        }
    }

    @Test func requiresWellFormedX5C() throws {
        let f = try fixture()
        for chain in [[], ["not-base64"], [Self.leaf, "bad!"]] {
            let parsed = try credential(signer: f.signer, chain: chain)
            #expect(throws: WalletError.self) { try IssuerX509Verifier.certificateChain(of: parsed) }
        }
        let parsed = try credential(signer: f.signer, chain: [Self.leaf],
                                    headerChanges: ["crit": ["unknown"]])
        #expect(throws: WalletError.self) { try IssuerX509Verifier.certificateChain(of: parsed) }
    }

    @Test func testPolicyIsScopedToEUDIIssuerAndTypes() {
        let source = EUDITestIssuerCertificateTrustSource()
        #expect(!source.supports(issuer: Self.issuer, vct: Self.diplomaVCT)) // EAA, not PubEAA
        #expect(!source.supports(issuer: Self.issuer, vct: "urn:eu.europa.ec.eudi:learning:credential:1"))
        #expect(source.supports(issuer: Self.issuer, vct: Self.ehicVCT))
        #expect(source.supports(issuer: Self.issuer, vct: Self.healthIDVCT))
        #expect(!source.supports(issuer: Self.issuer, vct: "urn:other"))
        #expect(!source.supports(issuer: URL(string: "https://example.com")!, vct: Self.diplomaVCT))
        #expect(!source.supports(issuer: URL(string: "https://example.com")!, vct: Self.ehicVCT))
        #expect(!source.supports(issuer: URL(string: "https://example.com")!, vct: Self.healthIDVCT))
        #expect(!source.supports(issuer: Self.issuer, vct: "eu.europa.ec.eudi.ehic.1")) // mdoc
        #expect(!source.supports(issuer: Self.issuer, vct: "eu.europa.ec.eudi.hiid.1")) // mdoc
    }
}

private nonisolated struct TestIssuerTrustSource: IssuerCertificateTrustSource {
    let root: Data

    func supports(issuer: URL, vct: String) -> Bool {
        issuer.absoluteString == "https://issuer.eudiw.dev" && vct == "urn:eu.europa.ec.eudi:diploma:1:1"
    }

    func trustedRoots(for chainDER: [Data], issuer: URL, vct: String) async throws -> [Data] {
        [root]
    }
}

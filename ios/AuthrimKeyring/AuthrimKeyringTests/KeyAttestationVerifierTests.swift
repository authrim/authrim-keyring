import CryptoKit
import Foundation
import Testing
@testable import AuthrimKeyring

/// Test-only CA, leaf certificate and signing scalar. These are fixtures, never production trust roots.
@Suite
struct KeyAttestationVerifierTests {
    nonisolated static let root = "MIIBnTCCAUOgAwIBAgIUOq6Oeno8H5ZfXVeXWduV8jRnA18wCgYIKoZIzj0EAwIwHDEaMBgGA1UEAwwRS2V5cmluZyBUZXN0IFJvb3QwHhcNMjYxMTA4MjIzNjUyWhcNMzYxMTA1MjIzNjUyWjAcMRowGAYDVQQDDBFLZXlyaW5nIFRlc3QgUm9vdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEkAij9Poz2f3ZsisHSkBXD7GrENKiOiMLuYteX5cRjp1kh1zmKaJoPA+RjcHwxf3T8l3wmMpjz709qjsdD3/x+jYzBhMB0GA1UdDgQWBBQOEkjWw2iaHMWL0aL+iw5Iw9RKfzAfBgNVHSMEGDAWgBQOEkjWw2iaHMWL0aL+iw5Iw9RKfzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAgNIADBFAiEAk716FxcyloVJ0i58cOPVpvmqgXubusMDARE9RgcxbPUCIBYBZfwc2tApjvmwYHGwP5VmjMCGfg8ljfvYoCKdrnkq"
    nonisolated static let leaf = "MIIBsjCCAVmgAwIBAgIULyLT1RfWogoqfQDef5rYTrJ4HA4wCgYIKoZIzj0EAwIwHDEaMBgGA1UEAwwRS2V5cmluZyBUZXN0IFJvb3QwHhcNMjYxMTA4MjIzNjUyWhcNMzYxMTA1MjIzNjUyWjAgMR4wHAYDVQQDDBVLZXlyaW5nIFRlc3QgUHJvdmlkZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARR31nbuJYuYLb8LYVWYmvOcjq0hgp5A7SiTjId7jECfiHQHinEOesbHdCJuoeGQ93ZogVauY4lJuY4lu7I0cX/o3UwczAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQU8OBiwPB7F7r3eG34pd/1oS/B9e4wHwYDVR0jBBgwFoAUDhJI1sNomhzFi9Gi/osOSMPUSn8wCgYIKoZIzj0EAwIDRwAwRAIgD4dC3NAoPGMZjZcbEJnadZQOX2fEb9ECwaTsPsYCGB8CIGk2qqZ8rU0YwcEdH26WjKDhXuHSKT/WY6f5Yb4Tk8ST"
    nonisolated static let scalar = "2pM59XEWMr/M0XYWM8zm7wL59snhsCPnozvreyaWEHE="
    private static let now = Date(timeIntervalSince1970: 1_794_182_400)
    private static let high = KeyAttestationRequirements(
        acceptedKeyStorage: ["iso_18045_high"], acceptedUserAuthentication: ["iso_18045_high"])

    private func fixture() throws -> (root: Data, signer: P256.Signing.PrivateKey, holder: PublicJWK) {
        let root = try #require(Data(base64Encoded: Self.root))
        let scalar = try #require(Data(base64Encoded: Self.scalar))
        let signer = try P256.Signing.PrivateKey(rawRepresentation: scalar)
        let holderKey = P256.Signing.PrivateKey()
        let holder = try #require(PublicJWK(x963: holderKey.publicKey.x963Representation))
        return (root, signer, holder)
    }

    private func attestation(
        signer: P256.Signing.PrivateKey, holder: PublicJWK,
        headerChanges: [String: Any] = [:], payloadChanges: [String: Any] = [:]
    ) throws -> String {
        var header: [String: Any] = [
            "typ": "key-attestation+jwt", "alg": "ES256", "x5c": [Self.leaf],
        ]
        var payload: [String: Any] = [
            "iat": 1_794_182_390, "exp": 1_794_186_000, "nonce": "fresh-nonce",
            "attested_keys": [holder.proofMembers],
            "key_storage": ["iso_18045_high"],
            "user_authentication": ["iso_18045_high"],
        ]
        header.merge(headerChanges) { _, new in new }
        payload.merge(payloadChanges) { _, new in new }
        return try JWS.make(header: header, payload: payload) { input in
            try signer.signature(for: input).rawRepresentation
        }
    }

    @Test func acceptsTrustedProviderAttestation() throws {
        let f = try fixture()
        let jwt = try attestation(signer: f.signer, holder: f.holder)
        let validated = try KeyAttestationVerifier.validate(
            jwt, holderKey: f.holder, nonce: "fresh-nonce", requirements: Self.high,
            trustedRootDER: [f.root], now: Self.now)
        #expect(validated == jwt)
    }

    @Test func requiresAPinnedTrustRoot() throws {
        let f = try fixture()
        let jwt = try attestation(signer: f.signer, holder: f.holder)
        #expect(throws: KeyAttestationValidationError.missingTrustAnchor) {
            try KeyAttestationVerifier.validate(
                jwt, holderKey: f.holder, nonce: "fresh-nonce", requirements: Self.high,
                trustedRootDER: [], now: Self.now)
        }
    }

    @Test func rejectsAKeyNotNamedByTheAttestation() throws {
        let f = try fixture()
        let other = try #require(PublicJWK(x963: P256.Signing.PrivateKey().publicKey.x963Representation))
        let jwt = try attestation(signer: f.signer, holder: other)
        #expect(throws: KeyAttestationValidationError.wrongHolderKey) {
            try KeyAttestationVerifier.validate(
                jwt, holderKey: f.holder, nonce: "fresh-nonce", requirements: Self.high,
                trustedRootDER: [f.root], now: Self.now)
        }
    }

    @Test func rejectsInsufficientAssuranceAndWrongNonce() throws {
        let f = try fixture()
        let low = try attestation(signer: f.signer, holder: f.holder,
                                  payloadChanges: ["key_storage": ["iso_18045_basic"]])
        #expect(throws: KeyAttestationValidationError.insufficientAssurance) {
            try KeyAttestationVerifier.validate(
                low, holderKey: f.holder, nonce: "fresh-nonce", requirements: Self.high,
                trustedRootDER: [f.root], now: Self.now)
        }
        let valid = try attestation(signer: f.signer, holder: f.holder)
        #expect(throws: KeyAttestationValidationError.wrongNonce) {
            try KeyAttestationVerifier.validate(
                valid, holderKey: f.holder, nonce: "other-nonce", requirements: Self.high,
                trustedRootDER: [f.root], now: Self.now)
        }
    }

    @Test func rejectsExpiredOrSelfSignedProviderEvidence() throws {
        let f = try fixture()
        let expired = try attestation(signer: f.signer, holder: f.holder,
                                      payloadChanges: ["exp": 1_794_182_399])
        #expect(throws: KeyAttestationValidationError.invalidTime) {
            try KeyAttestationVerifier.validate(
                expired, holderKey: f.holder, nonce: "fresh-nonce", requirements: Self.high,
                trustedRootDER: [f.root], now: Self.now)
        }
        let rootInChain = try attestation(signer: f.signer, holder: f.holder,
                                          headerChanges: ["x5c": [Self.leaf, Self.root]])
        #expect(throws: KeyAttestationValidationError.untrustedCertificate) {
            try KeyAttestationVerifier.validate(
                rootInChain, holderKey: f.holder, nonce: "fresh-nonce", requirements: Self.high,
                trustedRootDER: [f.root], now: Self.now)
        }
    }

    @Test func rejectsUnsupportedHeadersAndInvalidSignature() throws {
        let f = try fixture()
        let wrongType = try attestation(
            signer: f.signer, holder: f.holder,
            headerChanges: ["typ": "JWT"])
        #expect(throws: KeyAttestationValidationError.unsupportedHeader) {
            try KeyAttestationVerifier.validate(
                wrongType, holderKey: f.holder, nonce: "fresh-nonce", requirements: Self.high,
                trustedRootDER: [f.root], now: Self.now)
        }

        let noChain = try attestation(
            signer: f.signer, holder: f.holder,
            headerChanges: ["x5c": []])
        #expect(throws: KeyAttestationValidationError.unsupportedHeader) {
            try KeyAttestationVerifier.validate(
                noChain, holderKey: f.holder, nonce: "fresh-nonce", requirements: Self.high,
                trustedRootDER: [f.root], now: Self.now)
        }

        let otherSigner = P256.Signing.PrivateKey()
        let badSignature = try attestation(signer: otherSigner, holder: f.holder)
        #expect(throws: KeyAttestationValidationError.invalidSignature) {
            try KeyAttestationVerifier.validate(
                badSignature, holderKey: f.holder, nonce: "fresh-nonce", requirements: Self.high,
                trustedRootDER: [f.root], now: Self.now)
        }
    }
}

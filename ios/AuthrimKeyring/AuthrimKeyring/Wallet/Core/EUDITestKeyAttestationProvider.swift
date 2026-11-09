import Foundation
import Security

/// Uses the European Commission's public test wallet provider for the EUDI test issuer only.
/// The JWK route does not verify an iOS platform attestation. Its `iso_18045_high` assertion is
/// suitable for interoperability testing, not evidence of a production device's assurance level.
nonisolated struct EUDITestKeyAttestationProvider: KeyAttestationProvider, KeyAttestationTrustSource {
    private static let issuerIdentifier = "https://issuer.eudiw.dev"
    private static let providerOrigin = URL(string: "https://wallet-provider.eudiw.dev")!
    private static let attestationEndpoint = URL(string: "https://wallet-provider.eudiw.dev/key-attestation/jwk-set")!
    private static let validatorOrigin = URL(string: "https://trust-validator.eudiw.dev")!
    private static let trustEndpoint = URL(string: "https://trust-validator.eudiw.dev/trust")!

    private let http: WalletHTTP

    init(http: WalletHTTP = WalletHTTP()) {
        self.http = http
    }

    func supports(issuer: URL) -> Bool {
        issuer.absoluteString == Self.issuerIdentifier
    }

    func attestation(for holderKey: PublicJWK, nonce: String?, issuer: URL) async throws -> String {
        try requireTestIssuer(issuer)
        guard holderKey.cryptoKey != nil else {
            throw WalletError.keyUnavailable("The holder public key is invalid.")
        }
        if let nonce, (nonce.isEmpty || nonce.utf8.count > 1024) {
            throw WalletError.invalidIssuer("The credential nonce is invalid.")
        }

        var providerJWK = holderKey.proofMembers
        providerJWK["alg"] = "ES256"
        var request: [String: Any] = ["jwkSet": ["keys": [providerJWK]]]
        if let nonce { request["nonce"] = nonce }
        let body = try JSONSerialization.data(withJSONObject: request)
        let response = try await http.send(
            Self.attestationEndpoint, method: "POST",
            headers: ["Content-Type": "application/json"], body: body,
            origin: Self.providerOrigin)
        guard response.status == 200,
              let object = (try? JSONSerialization.jsonObject(with: response.data)) as? [String: Any],
              let jwt = object["keyAttestation"] as? String,
              jwt.utf8.count <= 64 * 1024, JWS.parse(jwt) != nil
        else { throw WalletError.network("The EUDI test wallet provider did not issue a key attestation.") }
        return jwt
    }

    func trustedRoots(for attestation: String, issuer: URL) async throws -> [Data] {
        try requireTestIssuer(issuer)
        guard attestation.utf8.count <= 64 * 1024,
              let parts = JWS.parse(attestation),
              parts.header["typ"] as? String == "key-attestation+jwt",
              let chain = parts.header["x5c"] as? [String],
              (1...8).contains(chain.count),
              chain.allSatisfy({ Self.certificateDER($0) != nil })
        else { throw WalletError.invalidIssuer("The key attestation certificate chain is invalid.") }

        // The validator receives only public certificates. Its trust decision supplies an
        // independent CA anchor; neither the attestation's x5c nor the provider JWKS is an anchor.
        let body = try JSONSerialization.data(withJSONObject: [
            "chain": chain,
            "verificationContext": "WalletProviderAttestation",
        ])
        let response = try await http.send(
            Self.trustEndpoint, method: "POST",
            headers: ["Content-Type": "application/json"], body: body,
            origin: Self.validatorOrigin)
        guard response.status == 200,
              let object = (try? JSONSerialization.jsonObject(with: response.data)) as? [String: Any],
              object["trusted"] as? Bool == true,
              let encodedAnchor = object["trustAnchor"] as? String,
              let anchor = Self.certificateDER(encodedAnchor),
              !chain.compactMap(Self.certificateDER).contains(anchor),
              SecCertificateCreateWithData(nil, anchor as CFData) != nil
        else { throw WalletError.invalidIssuer("The EUDI test wallet provider certificate is not trusted.") }
        return [anchor]
    }

    private func requireTestIssuer(_ issuer: URL) throws {
        guard supports(issuer: issuer) else {
            throw WalletError.unsupportedKeyAttestation
        }
    }

    /// The trust validator returns unpadded standard Base64, whereas x5c commonly uses padding.
    private static func certificateDER(_ encoded: String) -> Data? {
        guard !encoded.isEmpty, encoded.utf8.count <= 16 * 1024 else { return nil }
        let bare = encoded.prefix(while: { $0 != "=" })
        let suppliedPadding = encoded.dropFirst(bare.count)
        let alphabet = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        guard suppliedPadding.count <= 2, suppliedPadding.allSatisfy({ $0 == "=" }),
              bare.unicodeScalars.allSatisfy(alphabet.contains), bare.count % 4 != 1
        else { return nil }
        let padded = String(bare) + String(repeating: "=", count: (4 - bare.count % 4) % 4)
        return Data(base64Encoded: padded)
    }
}

import CryptoKit
import Foundation

/// An ephemeral DPoP key for one issuance session. The same key signs the token request and every
/// request made with its access token; each HTTP request gets a fresh proof and `jti` (RFC 9449).
nonisolated struct WalletDPoPKey: Sendable {
    let publicJWK: PublicJWK
    private let privateKey: P256.Signing.PrivateKey

    init() throws {
        let key = P256.Signing.PrivateKey()
        guard let jwk = PublicJWK(x963: key.publicKey.x963Representation) else {
            throw WalletError.keyUnavailable("The DPoP public key could not be read.")
        }
        privateKey = key
        publicJWK = jwk
    }

    /// Makes a proof for the exact request method and URL. `ath` is included only when presenting
    /// an access token; `nonce` is included when the server has supplied a DPoP-Nonce challenge.
    func proof(
        method: String, url: URL, accessToken: String? = nil, nonce: String? = nil,
        issuedAt: Date = .now
    ) throws -> String {
        guard !method.isEmpty,
              method.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) })
        else { throw WalletError.invalidIssuer("The DPoP HTTP method is invalid.") }
        _ = try WalletHTTP.requireHTTPS(url, "The DPoP request URL")
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            throw WalletError.invalidIssuer("The DPoP request URL is invalid.")
        }
        components.query = nil
        components.fragment = nil
        guard let target = components.url?.absoluteString else {
            throw WalletError.invalidIssuer("The DPoP request URL is invalid.")
        }

        var payload: [String: Any] = [
            "jti": UUID().uuidString,
            "htm": method.uppercased(),
            "htu": target,
            "iat": Int(issuedAt.timeIntervalSince1970),
        ]
        if let accessToken {
            guard !accessToken.isEmpty, accessToken.utf8.allSatisfy({ $0 < 128 }) else {
                throw WalletError.invalidIssuer("The DPoP access token is invalid.")
            }
            payload["ath"] = Base64URL.encode(Data(SHA256.hash(data: Data(accessToken.utf8))))
        }
        if let nonce { payload["nonce"] = nonce }
        let header: [String: Any] = [
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": publicJWK.proofMembers,
        ]
        return try JWS.make(header: header, payload: payload) { message in
            try privateKey.signature(for: message).rawRepresentation
        }
    }

    /// The OAuth client-attestation proof uses the same key named by the Wallet Attestation's
    /// `cnf.jwk`. EUDI's authorization server expects its issuer identifier as `aud`.
    func clientAttestationPoP(
        clientID: String, audience: URL, challenge: String? = nil, issuedAt: Date
    ) throws -> String {
        _ = try WalletHTTP.requireHTTPS(audience, "The authorization server")
        guard !clientID.isEmpty, clientID.utf8.count <= 512 else {
            throw WalletError.invalidIssuer("The wallet attestation client ID is invalid.")
        }
        var payload: [String: Any] = [
                "iss": clientID,
                "aud": audience.absoluteString,
                "jti": UUID().uuidString,
                "iat": Int(issuedAt.timeIntervalSince1970),
        ]
        if let challenge { payload["challenge"] = challenge }
        return try JWS.make(
            header: ["typ": "oauth-client-attestation-pop+jwt", "alg": "ES256"],
            payload: payload) { message in
                try privateKey.signature(for: message).rawRepresentation
            }
    }
}

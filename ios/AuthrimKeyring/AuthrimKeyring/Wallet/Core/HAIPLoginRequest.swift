import CryptoKit
import Foundation
import Security

/// A `haip-vp:` (or `openid4vp:`) link whose request is a signed request object for the Authrim admin
/// console sign-in: `client_id` of the `x509_hash` prefix and a `request_uri` by reference.
nonisolated struct HAIPLoginLink: Sendable, Equatable {
    static let schemes: Set<String> = ["haip-vp", "openid4vp"]
    static let clientIDPrefix = "x509_hash:"
    static let requestPathPrefix = "/vp/login/request/"

    let clientID: String
    let requestURI: URL

    /// Whether the text is a sign-in link (the `x509_hash` client id tells it from the step-up link).
    static func isLoginLink(_ text: String) -> Bool {
        guard let components = URLComponents(string: text.trimmingCharacters(in: .whitespacesAndNewlines)),
              let scheme = components.scheme?.lowercased(), schemes.contains(scheme) else { return false }
        return components.queryItems?.contains { $0.name == "client_id" && ($0.value ?? "").hasPrefix(clientIDPrefix) } == true
    }

    init(_ text: String) throws {
        guard let components = URLComponents(string: text.trimmingCharacters(in: .whitespacesAndNewlines)),
              let scheme = components.scheme?.lowercased(), Self.schemes.contains(scheme)
        else { throw WalletError.notAPresentationRequest }
        let items = components.queryItems ?? []
        func value(_ name: String) -> String? {
            let found = items.filter { $0.name == name }
            return found.count == 1 ? found[0].value : nil
        }
        guard items.allSatisfy({ ["client_id", "request_uri", "request_uri_method"].contains($0.name) }),
              let clientID = value("client_id"), clientID.hasPrefix(Self.clientIDPrefix),
              Base64URL.decode(String(clientID.dropFirst(Self.clientIDPrefix.count)))?.count == 32,
              let uri = value("request_uri"), value("request_uri_method").map({ $0 == "get" }) ?? true,
              let url = URL(string: uri), let checked = try? WalletHTTP.requireHTTPS(url, "The request URI"),
              checked.query == nil, checked.fragment == nil, checked.port == nil,
              Self.isRequestPath(checked.path(percentEncoded: true))
        else { throw WalletError.notAPresentationRequest }
        self.clientID = clientID
        self.requestURI = checked
    }

    /// `/vp/login/request/<id>` with the server's id form, nothing more.
    static func isRequestPath(_ path: String) -> Bool {
        guard path.hasPrefix(requestPathPrefix) else { return false }
        let encoded = String(path.dropFirst(requestPathPrefix.count))
        guard encoded.count <= 256, let id = encoded.removingPercentEncoding else { return false }
        return id.wholeMatch(of: /g[0-9]{1,6}:[a-z0-9-]{1,32}:[0-9]{1,6}:vp_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/) != nil
    }
}

/// A sign-in request that passed every check, ready to be shown and answered.
nonisolated struct HAIPLoginRequest: Sendable, Identifiable {
    let id = UUID()
    let clientID: String
    let verifierHost: String
    let responseURI: URL
    let nonce: String
    let state: String
    let expiresAt: Date
    let queryID: String
    /// The verifier's ephemeral P-256 key and its `kid`, and the content encryption chosen from the offered ones.
    let encryptionKey: PublicJWK
    let encryptionKeyID: String?
    let enc: String
    var credential: StoredCredential
    var candidates: [StoredCredential] = []

    func answering(with chosen: StoredCredential) -> HAIPLoginRequest {
        guard candidates.contains(where: { $0.id == chosen.id }) else { return self }
        var copy = self
        copy.credential = chosen
        return copy
    }
}

/// The checks of a sign-in request object. The signature, the `x509_hash` binding and the chain to
/// a pinned Authrim root are checked by the caller before the payload gets here.
nonisolated enum HAIPLoginRequestValidator {
    static let selfIssuedAudience = "https://self-issued.me/v2"
    static let maxLifetime: TimeInterval = 600
    static let clockSkew: TimeInterval = 60
    private static let refusedMembers: Set<String> = [
        "transaction_data", "presentation_definition", "presentation_definition_uri", "scope", "request_uri",
    ]

    static func validate(
        payload: [String: Any], link: HAIPLoginLink, verifierHost: String,
        credentials: [StoredCredential], adminVCTs: Set<String>, now: Date
    ) throws -> HAIPLoginRequest {
        guard payload.keys.allSatisfy({ !refusedMembers.contains($0) }) else {
            throw WalletError.invalidRequest("The request asks for something Keyring does not support.")
        }
        let audience = payload["aud"]
        guard (audience as? String) == selfIssuedAudience || (audience as? [String]) == [selfIssuedAudience] else {
            throw WalletError.invalidRequest("The request is addressed to another wallet.")
        }
        guard payload["client_id"] as? String == link.clientID, payload["response_type"] as? String == "vp_token",
              payload["response_mode"] as? String == "direct_post.jwt",
              let responseText = payload["response_uri"] as? String, let responseURL = URL(string: responseText),
              let responseURI = try? WalletHTTP.requireHTTPS(responseURL, "The response URI"),
              responseURI.host?.lowercased() == verifierHost, responseURI.port == nil,
              responseURI.query == nil, responseURI.fragment == nil
        else { throw WalletError.untrustedVerifier("The request must be answered to its own verifier.") }
        guard let nonce = payload["nonce"] as? String, (16...256).contains(nonce.count),
              let state = payload["state"] as? String, !state.isEmpty, state.count <= 256,
              let exp = payload["exp"] as? Double, let iat = payload["iat"] as? Double
        else { throw WalletError.invalidRequest("The request is incomplete.") }
        let expiresAt = Date(timeIntervalSince1970: exp)
        guard expiresAt > now, iat <= now.timeIntervalSince1970 + clockSkew, exp - iat <= maxLifetime else {
            throw WalletError.invalidRequest("The request has expired.")
        }
        let (key, keyID, enc) = try encryption(payload["client_metadata"])
        let query = try dcql(payload["dcql_query"])

        let matching = credentials
            .filter { $0.issuer.host?.lowercased() == verifierHost && $0.issuer.port == nil && query.vcts.contains($0.vct) && adminVCTs.contains($0.vct) }
            .filter { $0.expiresAt.map { $0 > now } ?? true }
            .filter { carriesPlainClaims($0, query.claimNames) }
            .filter { credential in
                query.authorityKeyIDs.isEmpty || carriesAuthority(credential, anyOf: query.authorityKeyIDs)
            }
        let candidates = PresentationRequestValidator.preferred(matching, for: .enroll)
        guard let credential = candidates.first else { throw WalletError.noMatchingCredential }
        var request = HAIPLoginRequest(
            clientID: link.clientID, verifierHost: verifierHost, responseURI: responseURI, nonce: nonce,
            state: state, expiresAt: expiresAt, queryID: query.id, encryptionKey: key,
            encryptionKeyID: keyID, enc: enc, credential: credential)
        request.candidates = candidates
        return request
    }

    /// The one P-256 encryption key of `client_metadata` and the strongest content encryption offered.
    private static func encryption(_ value: Any?) throws -> (PublicJWK, String?, String) {
        guard let metadata = value as? [String: Any],
              let keys = (metadata["jwks"] as? [String: Any])?["keys"] as? [[String: Any]], keys.count == 1,
              keys[0]["d"] == nil, keys[0]["kty"] as? String == "EC", keys[0]["crv"] as? String == "P-256",
              (keys[0]["use"] as? String).map({ $0 == "enc" }) ?? true,
              (keys[0]["alg"] as? String).map({ $0 == "ECDH-ES" }) ?? true,
              let kid = keys[0]["kid"] as? String, !kid.isEmpty, kid.count <= 512,
              let key = PublicJWK(from: keys[0]), key.cryptoKey != nil,
              let offered = metadata["encrypted_response_enc_values_supported"] as? [String],
              let enc = WalletJWE.supportedContentEncryption.first(where: offered.contains)
        else { throw WalletError.invalidRequest("The request has no response encryption Keyring supports.") }
        return (key, kid, enc)
    }

    private struct Query {
        let id: String
        let vcts: [String]
        let authorityKeyIDs: [Data]
        let claimNames: [String]
    }

    /// One `dc+sd-jwt` query for an admin credential, asking for plain claims only. A condition the
    /// wallet does not apply is refused rather than ignored.
    private static func dcql(_ value: Any?) throws -> Query {
        let unsupported = WalletError.invalidRequest("The request has conditions Keyring does not support.")
        guard let query = value as? [String: Any], query.keys.allSatisfy({ $0 == "credentials" }),
              let credentials = query["credentials"] as? [[String: Any]], credentials.count == 1,
              let id = credentials[0]["id"] as? String, !id.isEmpty, id.count <= 64,
              credentials[0]["format"] as? String == "dc+sd-jwt",
              credentials[0].keys.allSatisfy({ ["id", "format", "meta", "claims", "trusted_authorities"].contains($0) }),
              let meta = credentials[0]["meta"] as? [String: Any], meta.keys.allSatisfy({ $0 == "vct_values" }),
              let vcts = meta["vct_values"] as? [String], !vcts.isEmpty
        else { throw unsupported }
        var claimNames: [String] = []
        if let raw = credentials[0]["claims"] {
            guard let claims = raw as? [[String: Any]], claims.allSatisfy({ $0.keys.allSatisfy { $0 == "path" } }) else { throw unsupported }
            let paths = claims.compactMap { ($0["path"] as? [String])?.joined(separator: ".") }
            guard paths.count == claims.count, Set(paths).isSubset(of: ["sub", "tenant_id"]) else {
                throw WalletError.invalidRequest("The request asks for more than the admin credential needs.")
            }
            claimNames = paths
        }
        var identifiers: [Data] = []
        if let raw = credentials[0]["trusted_authorities"] {
            guard let list = raw as? [[String: Any]], !list.isEmpty, list.count <= 8 else { throw unsupported }
            for entry in list {
                guard entry.keys.allSatisfy({ ["type", "values"].contains($0) }), entry["type"] as? String == "aki",
                      let values = entry["values"] as? [String], !values.isEmpty, values.count <= 8 else { throw unsupported }
                for text in values {
                    guard let decoded = Base64URL.decode(text), !decoded.isEmpty else { throw unsupported }
                    identifiers.append(decoded)
                }
            }
        }
        return Query(id: id, vcts: vcts, authorityKeyIDs: identifiers, claimNames: claimNames)
    }

    /// The requested claims must be plain claims of the issuer JWT: the answer carries no disclosure.
    static func carriesPlainClaims(_ credential: StoredCredential, _ names: [String]) -> Bool {
        guard !names.isEmpty else { return true }
        guard let parsed = try? ParsedSDJWT(credential.sdJwt), let parts = JWS.parse(parsed.issuerJWT) else { return false }
        return names.allSatisfy { parts.payload[$0] != nil }
    }

    /// A credential matches an `aki` request when the Authority Key Identifier of a certificate in its
    /// own `x5c` equals a requested value (OpenID4VP 6.1.1.1). A Subject Key Identifier alone never does.
    static func carriesAuthority(_ credential: StoredCredential, anyOf wanted: [Data]) -> Bool {
        guard let parsed = try? ParsedSDJWT(credential.sdJwt),
              let chain = try? IssuerX509Verifier.certificateChain(of: parsed) else { return false }
        return chain.contains { certificate in
            CertificateKeyIdentifiers.authorityKeyIdentifier(of: certificate).map(wanted.contains) ?? false
        }
    }
}

import Foundation

/// A credential configuration the wallet can use: SD-JWT VC, ES256, `jwk` key binding.
nonisolated struct VerifiedConfiguration: Sendable, Equatable {
    let id: String
    let vct: String
    let name: String
    let claimNames: [String]
}

/// Issuer and authorization server metadata after the checks of OpenID4VCI 1.0 section 12 and RFC 8414.
nonisolated struct VerifiedIssuer: Sendable {
    let issuer: URL
    let displayName: String?
    let credentialEndpoint: URL
    let nonceEndpoint: URL?
    let tokenEndpoint: URL
    let configuration: VerifiedConfiguration
}

nonisolated enum IssuerMetadata {
    /// Inserts `/.well-known/<suffix>` between host and path (RFC 8615, OpenID4VCI 12.2.2, RFC 8414 3.1).
    static func wellKnownURL(for identifier: URL, suffix: String) -> URL? {
        guard var components = URLComponents(url: identifier, resolvingAgainstBaseURL: false) else { return nil }
        // Keep the identifier's encoding: `%3A` and `:` need not name the same resource (RFC 3986 2.2).
        var path = components.percentEncodedPath
        if path == "/" { path = "" }
        components.percentEncodedPath = "/.well-known/\(suffix)" + path
        components.query = nil
        components.fragment = nil
        return components.url
    }

    /// The issuer identifier must be an https URL without query, fragment or user info, and its path
    /// must already be normalized (no empty, `.` or `..` segments, encoded or not), so the well-known
    /// URL built from it names the same path the identifier does.
    static func issuerURL(_ text: String) throws -> URL {
        guard let url = URL(string: text), let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.query == nil, components.fragment == nil,
              (try? WalletHTTP.requireHTTPS(url, "The issuer")) != nil,
              isNormalizedPath(components.percentEncodedPath)
        else { throw WalletError.invalidIssuer("The credential issuer is not a valid https identifier.") }
        return url
    }

    private static func isNormalizedPath(_ path: String) -> Bool {
        if path.isEmpty || path == "/" { return true }
        guard path.hasPrefix("/") else { return false }
        return path.dropFirst().split(separator: "/", omittingEmptySubsequences: false).allSatisfy { segment in
            let decoded = segment.removingPercentEncoding ?? String(segment)
            return !decoded.isEmpty && decoded != "." && decoded != ".." && !decoded.contains("/")
        }
    }

    /// Fetches and validates everything the wallet needs for the offer. `preferredLanguages` orders display names.
    static func resolve(
        offer: ParsedOffer, http: WalletHTTP, preferredLanguages: [String]
    ) async throws -> VerifiedIssuer {
        let issuer = try issuerURL(offer.credentialIssuer)
        guard let metadataURL = wellKnownURL(for: issuer, suffix: "openid-credential-issuer") else {
            throw WalletError.invalidIssuer("The issuer metadata URL cannot be built.")
        }
        let metadata = try await http.getJSON(metadataURL, origin: issuer)
        guard (metadata["credential_issuer"] as? String) == offer.credentialIssuer else {
            throw WalletError.invalidIssuer("The issuer metadata names a different credential issuer.")
        }

        // Exactly one authorization server; none listed means the issuer is its own.
        let servers = (metadata["authorization_servers"] as? [String]) ?? [offer.credentialIssuer]
        guard servers.count == 1, let serverIdentifier = servers.first else {
            throw WalletError.invalidIssuer("Exactly one authorization server is supported.")
        }
        if let named = offer.authorizationServer, named != serverIdentifier {
            throw WalletError.invalidIssuer("The offer names an authorization server the issuer does not list.")
        }
        let server = try issuerURL(serverIdentifier)
        guard let serverMetadataURL = wellKnownURL(for: server, suffix: "oauth-authorization-server") else {
            throw WalletError.invalidIssuer("The authorization server metadata URL cannot be built.")
        }
        let serverMetadata = try await http.getJSON(serverMetadataURL)
        guard (serverMetadata["issuer"] as? String) == serverIdentifier else {
            throw WalletError.invalidIssuer("The authorization server metadata names a different issuer.")
        }
        if let grants = serverMetadata["grant_types_supported"] as? [String],
           !grants.contains(CredentialOfferParser.preAuthorizedGrant) {
            throw WalletError.invalidIssuer("The authorization server does not support the pre-authorized code grant.")
        }

        let credentialEndpoint = try sameOriginEndpoint(metadata["credential_endpoint"], issuer, "credential_endpoint")
        let tokenEndpoint = try sameOriginEndpoint(serverMetadata["token_endpoint"], issuer, "token_endpoint")
        var nonceEndpoint: URL?
        if metadata["nonce_endpoint"] != nil {
            nonceEndpoint = try sameOriginEndpoint(metadata["nonce_endpoint"], issuer, "nonce_endpoint")
        }

        let configurations = metadata["credential_configurations_supported"] as? [String: Any] ?? [:]
        var chosen: VerifiedConfiguration?
        for id in offer.configurationIds {
            if let raw = configurations[id] as? [String: Any],
               let configuration = configuration(id: id, raw: raw, languages: preferredLanguages) {
                chosen = configuration
                break
            }
        }
        guard let configuration = chosen else {
            throw WalletError.invalidIssuer("The offered credential is not one this wallet supports.")
        }
        return VerifiedIssuer(
            issuer: issuer, displayName: localizedName(metadata["display"], languages: preferredLanguages),
            credentialEndpoint: credentialEndpoint, nonceEndpoint: nonceEndpoint, tokenEndpoint: tokenEndpoint,
            configuration: configuration)
    }

    private static func sameOriginEndpoint(_ value: Any?, _ issuer: URL, _ name: String) throws -> URL {
        guard let text = value as? String, let url = URL(string: text),
              (try? WalletHTTP.requireHTTPS(url, name)) != nil
        else { throw WalletError.invalidIssuer("\(name) is missing or not an https URL.") }
        guard WalletHTTP.sameOrigin(url, issuer) else {
            throw WalletError.invalidIssuer("\(name) is not on the credential issuer's origin.")
        }
        return url
    }

    /// nil when the configuration is not dc+sd-jwt / ES256 / jwk binding.
    private static func configuration(id: String, raw: [String: Any], languages: [String]) -> VerifiedConfiguration? {
        // vct is shown verbatim on the detail screen, so it must already be clean display text.
        guard (raw["format"] as? String) == "dc+sd-jwt", let vct = raw["vct"] as? String,
              sanitize(vct, maxLength: 512) == vct,
              (raw["cryptographic_binding_methods_supported"] as? [String])?.contains("jwk") == true,
              (raw["credential_signing_alg_values_supported"] as? [Any])?.contains(where: { ($0 as? String) == "ES256" }) == true,
              let proofTypes = raw["proof_types_supported"] as? [String: Any],
              let jwtProof = proofTypes["jwt"] as? [String: Any],
              (jwtProof["proof_signing_alg_values_supported"] as? [String])?.contains("ES256") == true
        else { return nil }

        let credentialMetadata = raw["credential_metadata"] as? [String: Any]
        let name = localizedName(credentialMetadata?["display"], languages: languages) ?? sanitize(id) ?? id
        let claims = (credentialMetadata?["claims"] as? [[String: Any]]) ?? []
        let claimNames = claims.prefix(64).compactMap { claim -> String? in
            if let shown = localizedName(claim["display"], languages: languages) { return shown }
            let path = (claim["path"] as? [Any])?.compactMap { $0 as? String }
            return path?.last.flatMap(sanitize)
        }
        return VerifiedConfiguration(id: id, vct: vct, name: name, claimNames: claimNames)
    }

    // MARK: Display text

    /// Picks the `name` of a `[{name, locale}]` list: exact locale, same language, `en`, no locale, first.
    static func localizedName(_ value: Any?, languages: [String]) -> String? {
        guard let entries = value as? [[String: Any]] else { return nil }
        let named = entries.compactMap { entry -> (name: String, locale: String?)? in
            guard let name = (entry["name"] as? String).flatMap(sanitize) else { return nil }
            return (name, (entry["locale"] as? String)?.lowercased())
        }
        func language(_ tag: String) -> String { tag.lowercased().split(whereSeparator: { $0 == "-" || $0 == "_" }).first.map(String.init) ?? "" }
        for preferred in languages {
            let tag = preferred.lowercased().replacingOccurrences(of: "_", with: "-")
            if let match = named.first(where: { $0.locale == tag }) { return match.name }
            if let match = named.first(where: { $0.locale.map(language) == language(tag) }) { return match.name }
        }
        if let match = named.first(where: { $0.locale.map(language) == "en" }) { return match.name }
        return (named.first(where: { $0.locale == nil }) ?? named.first)?.name
    }

    /// Issuer-supplied text is shown to the user: drop control characters, cap the length.
    static func sanitize(_ text: String) -> String? { sanitize(text, maxLength: 120) }

    static func sanitize(_ text: String, maxLength: Int) -> String? {
        let cleaned = String(text.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) })
            .trimmingCharacters(in: .whitespaces)
        return cleaned.isEmpty ? nil : String(cleaned.prefix(maxLength))
    }
}

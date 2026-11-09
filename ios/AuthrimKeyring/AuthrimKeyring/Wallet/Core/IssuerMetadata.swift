import Foundation

/// A credential configuration the wallet can use: SD-JWT VC, ES256, `jwk` key binding.
nonisolated struct VerifiedConfiguration: Sendable, Equatable {
    let id: String
    let vct: String
    let name: String
    let claimNames: [String]
    let keyAttestationRequirements: KeyAttestationRequirements?
}

/// Issuer and authorization server metadata after the checks of OpenID4VCI 1.0 section 12 and RFC 8414.
nonisolated struct VerifiedIssuer: Sendable {
    let issuer: URL
    let authorizationServer: URL
    let displayName: String?
    let credentialEndpoint: URL
    let nonceEndpoint: URL?
    let tokenEndpoint: URL
    /// AS metadata advertises an ES256 DPoP proof algorithm (RFC 9449).
    let supportsDPoP: Bool
    /// AS metadata offers attestation-based client authentication at the Token Endpoint.
    let supportsWalletAttestation: Bool
    let configuration: VerifiedConfiguration
    let additionalConfigurations: [VerifiedConfiguration]

    var configurations: [VerifiedConfiguration] { [configuration] + additionalConfigurations }
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
        offer: ParsedOffer, http: WalletHTTP, preferredLanguages: [String],
        supportsKeyAttestation: Bool = false,
        canAuthenticateWithWalletAttestation: Bool = false
    ) async throws -> VerifiedIssuer {
        let issuer = try issuerURL(offer.credentialIssuer)
        guard let metadataURL = wellKnownURL(for: issuer, suffix: "openid-credential-issuer") else {
            throw WalletError.invalidIssuer("The issuer metadata URL cannot be built.")
        }
        let metadata = try await http.getJSON(
            metadataURL, origin: issuer, maxBytes: WalletHTTP.issuerMetadataLimit)
        guard (metadata["credential_issuer"] as? String) == offer.credentialIssuer else {
            throw WalletError.invalidIssuer("The issuer metadata names a different credential issuer.")
        }
        try requireSupportedEncryption(in: metadata)

        // Exactly one authorization server; only an omitted field means the issuer is its own.
        // A present but malformed value must not silently change where the one-time code goes.
        let servers: [String]
        if let advertised = metadata["authorization_servers"] {
            guard let listed = advertised as? [String] else {
                throw WalletError.invalidIssuer("The authorization server list is malformed.")
            }
            servers = listed
        } else {
            servers = [offer.credentialIssuer]
        }
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
        // RFC 8414 defaults an omitted grant list to authorization_code and implicit,
        // neither of which can redeem this offer. A malformed list is not an omission.
        let grants: [String]
        if let advertised = serverMetadata["grant_types_supported"] {
            guard let listed = advertised as? [String] else {
                throw WalletError.invalidIssuer("The authorization server grant list is malformed.")
            }
            grants = listed
        } else {
            grants = ["authorization_code", "implicit"]
        }
        guard grants.contains(CredentialOfferParser.preAuthorizedGrant) else {
            throw WalletError.invalidIssuer("The authorization server does not support the pre-authorized code grant.")
        }
        // OID4VCI 12.3 defaults this flag to false. Without anonymous access, this
        // wallet needs a usable WIA/DPoP path before it can send the one-time code.
        let allowsAnonymousTokenRequest: Bool
        if let advertised = serverMetadata["pre-authorized_grant_anonymous_access_supported"] {
            guard let flag = advertised as? NSNumber,
                  CFGetTypeID(flag) == CFBooleanGetTypeID() else {
                throw WalletError.invalidIssuer("The anonymous pre-authorized grant policy is malformed.")
            }
            allowsAnonymousTokenRequest = flag.boolValue
        } else {
            allowsAnonymousTokenRequest = false
        }
        let supportsDPoP = (serverMetadata["dpop_signing_alg_values_supported"] as? [String])?.contains("ES256") == true
        let supportsWalletAttestation = (serverMetadata["token_endpoint_auth_methods_supported"] as? [String])?
            .contains("attest_jwt_client_auth") == true
        guard allowsAnonymousTokenRequest ||
              (supportsWalletAttestation && supportsDPoP && canAuthenticateWithWalletAttestation) else {
            throw WalletError.invalidIssuer("The authorization server requires client authentication this wallet cannot provide.")
        }

        // The issuer and its authorization server may delegate endpoints to other HTTPS hosts.
        // Each endpoint must come from the metadata fetched and identity-checked above.
        let credentialEndpoint = try advertisedEndpoint(metadata["credential_endpoint"], "credential_endpoint")
        let tokenEndpoint = try advertisedEndpoint(serverMetadata["token_endpoint"], "token_endpoint")
        // The token request carries the one-time code. Keep it on the authorization server's
        // origin even if metadata advertises a different host (a conservative subset of RFC 8414).
        guard WalletHTTP.sameOrigin(tokenEndpoint, server) else {
            throw WalletError.invalidIssuer("The token endpoint is not on the authorization server's origin.")
        }
        var nonceEndpoint: URL?
        if metadata["nonce_endpoint"] != nil {
            nonceEndpoint = try advertisedEndpoint(metadata["nonce_endpoint"], "nonce_endpoint")
        }

        let configurations = metadata["credential_configurations_supported"] as? [String: Any] ?? [:]
        var supported: [VerifiedConfiguration] = []
        var requiresUnsupportedKeyAttestation = false
        for id in offer.configurationIds {
            guard let raw = configurations[id] as? [String: Any] else { continue }
            let proofTypes = raw["proof_types_supported"] as? [String: Any]
            let jwtProof = proofTypes?["jwt"] as? [String: Any]
            let attestationValue = jwtProof?["key_attestations_required"]
            if attestationValue != nil && !supportsKeyAttestation {
                requiresUnsupportedKeyAttestation = true
                continue
            }
            let requirements = try attestationValue.map(parseKeyAttestationRequirements)
            if let configuration = configuration(
                id: id, raw: raw, languages: preferredLanguages, keyAttestationRequirements: requirements)
            {
                supported.append(configuration)
            }
        }
        // The offer is presented as one set. Do not silently omit a type that needs an
        // unsupported holder proof and then redeem the code for only the other types.
        if requiresUnsupportedKeyAttestation { throw WalletError.unsupportedKeyAttestation }
        guard let configuration = supported.first else {
            throw WalletError.invalidIssuer("The offered credential is not one this wallet supports.")
        }
        return VerifiedIssuer(
            issuer: issuer, authorizationServer: server,
            displayName: localizedName(metadata["display"], languages: preferredLanguages),
            credentialEndpoint: credentialEndpoint, nonceEndpoint: nonceEndpoint, tokenEndpoint: tokenEndpoint,
            supportsDPoP: supportsDPoP, supportsWalletAttestation: supportsWalletAttestation,
            configuration: configuration, additionalConfigurations: Array(supported.dropFirst()))
    }

    private static func advertisedEndpoint(_ value: Any?, _ name: String) throws -> URL {
        guard let text = value as? String, let url = URL(string: text),
              (try? WalletHTTP.requireHTTPS(url, name)) != nil,
              url.fragment == nil
        else { throw WalletError.invalidIssuer("\(name) is missing or not an https URL.") }
        return url
    }

    /// Reject required JWE at preview time. Otherwise the one-time code would be spent before
    /// this wallet discovers that it cannot make the required request or decrypt the response.
    private static func requireSupportedEncryption(in metadata: [String: Any]) throws {
        for name in ["credential_request_encryption", "credential_response_encryption"] {
            guard let value = metadata[name] else { continue }
            guard let object = value as? [String: Any],
                  let required = object["encryption_required"] as? NSNumber,
                  CFGetTypeID(required) == CFBooleanGetTypeID() else {
                throw WalletError.invalidIssuer("The \(name) metadata is malformed.")
            }
            if required.boolValue { throw WalletError.unsupportedCredentialEncryption }
        }
    }

    /// nil when the configuration is not dc+sd-jwt / ES256 / jwk binding.
    private static func configuration(
        id: String, raw: [String: Any], languages: [String],
        keyAttestationRequirements: KeyAttestationRequirements?
    ) -> VerifiedConfiguration? {
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
        let name = localizedName(credentialMetadata?["display"], languages: languages)
            ?? sanitize(id) ?? String(vct.prefix(120))
        let claims = (credentialMetadata?["claims"] as? [[String: Any]]) ?? []
        let claimNames = claims.prefix(64).compactMap { claim -> String? in
            if let shown = localizedName(claim["display"], languages: languages) { return shown }
            let path = (claim["path"] as? [Any])?.compactMap { $0 as? String }
            return path?.last.flatMap(sanitize)
        }
        return VerifiedConfiguration(
            id: id, vct: vct, name: name, claimNames: claimNames,
            keyAttestationRequirements: keyAttestationRequirements)
    }

    private static func parseKeyAttestationRequirements(_ value: Any) throws -> KeyAttestationRequirements {
        guard let object = value as? [String: Any] else {
            throw WalletError.invalidIssuer("The key attestation requirements are malformed.")
        }
        func accepted(_ name: String) throws -> Set<String> {
            guard let value = object[name] else { return [] }
            guard let values = value as? [String], !values.isEmpty,
                  values.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 128 }) else {
                throw WalletError.invalidIssuer("The key attestation \(name) requirement is malformed.")
            }
            return Set(values)
        }
        return try KeyAttestationRequirements(
            acceptedKeyStorage: accepted("key_storage"),
            acceptedUserAuthentication: accepted("user_authentication"))
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
        let cleaned = String(text.unicodeScalars.filter {
            !CharacterSet.controlCharacters.contains($0) && $0.properties.generalCategory != .format
        })
            .trimmingCharacters(in: .whitespaces)
        return cleaned.isEmpty ? nil : String(cleaned.prefix(maxLength))
    }
}

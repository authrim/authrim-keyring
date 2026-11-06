import Foundation

/// An `openid4vp://` link (OpenID4VP 1.0, request passed by reference).
nonisolated struct PresentationLink: Sendable, Equatable {
    static let scheme = "openid4vp"

    let clientID: String
    let requestURI: URL

    /// Whether scanned or opened text is a presentation request link (the scheme is case-insensitive).
    static func isRequest(_ text: String) -> Bool {
        text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().hasPrefix(scheme + ":")
    }

    init(_ text: String) throws {
        guard Self.isRequest(text),
              let components = URLComponents(string: text.trimmingCharacters(in: .whitespacesAndNewlines))
        else { throw WalletError.notAPresentationRequest }
        let items = components.queryItems ?? []
        func value(_ name: String) -> String? {
            let found = items.filter { $0.name == name }
            return found.count == 1 ? found[0].value : nil
        }
        // Only the request by reference: a request in the link itself would be unsigned.
        guard items.allSatisfy({ ["client_id", "request_uri", "request_uri_method"].contains($0.name) }),
              let clientID = value("client_id"), let uri = value("request_uri"),
              value("request_uri_method").map({ $0 == "get" }) ?? true,
              let requestURI = URL(string: uri)
        else { throw WalletError.notAPresentationRequest }
        guard let checked = try? WalletHTTP.requireHTTPS(requestURI, "The request URI") else {
            throw WalletError.notAPresentationRequest
        }
        self.clientID = clientID
        self.requestURI = checked
    }
}

/// Why the admin console asks for the credential, from the request's `transaction_data`.
enum PresentationPurpose: String, Sendable {
    /// Confirm an important operation (second factor of an admin step-up).
    case stepUp = "step_up"
    /// Register this credential as one of the admin's second factors.
    case enroll
}

/// A request that passed every check, ready to be shown and answered.
nonisolated struct PresentationRequest: Sendable, Identifiable {
    let id = UUID()
    /// `decentralized_identifier:did:web:<host>`; also the key binding's audience.
    let clientID: String
    /// The verifier's host, the same as the issuer's host of `credential`.
    let verifierHost: String
    let responseURI: URL
    let nonce: String
    let state: String
    let expiresAt: Date
    /// The single `transaction_data` entry as received (its hash goes into the key binding).
    let transactionData: String
    let purpose: PresentationPurpose
    /// Tenant shown in the admin console.
    let tenant: String
    /// The stored credential that answers it.
    let credential: StoredCredential
}

/// The fixed checks of an administrator presentation request. A request is answered only when it
/// comes from the very issuer of a stored admin credential: signed with a key that issuer's
/// did:web publishes, answering to that same host, asking for that credential only.
nonisolated enum PresentationRequestValidator {
    static let clientIDPrefix = "decentralized_identifier:"
    static let selfIssuedAudience = "https://self-issued.me/v2"
    static let queryID = "admin"
    static let transactionDataType = "authrim_admin_step_up"
    static let maxLifetime: TimeInterval = 600
    static let clockSkew: TimeInterval = 60

    /// The did:web DID behind a client identifier, or nil for any other prefix.
    static func did(fromClientID clientID: String) -> String? {
        guard clientID.hasPrefix(clientIDPrefix) else { return nil }
        let did = String(clientID.dropFirst(clientIDPrefix.count))
        return DIDWeb.host(of: did) == nil ? nil : did
    }

    /// Checks the signed request object's payload. The signature is checked by the caller.
    static func validate(
        payload: [String: Any], link: PresentationLink, credentials: [StoredCredential], now: Date
    ) throws -> PresentationRequest {
        guard let did = did(fromClientID: link.clientID), let host = DIDWeb.host(of: did) else {
            throw WalletError.untrustedVerifier("Only requests from an Authrim issuer are answered.")
        }
        // A request for a wallet started by a link or a QR code is addressed to any such wallet
        // (OpenID4VP 1.0 section 5.8): another audience is someone else's request.
        let audience = payload["aud"]
        guard (audience as? String) == selfIssuedAudience || (audience as? [String]) == [selfIssuedAudience] else {
            throw WalletError.invalidRequest("The request is addressed to another wallet.")
        }
        guard (payload["client_id"] as? String) == link.clientID,
              link.requestURI.host?.lowercased() == host, link.requestURI.port == nil
        else { throw WalletError.untrustedVerifier("The request does not come from its verifier.") }

        guard payload["response_type"] as? String == "vp_token",
              payload["response_mode"] as? String == "direct_post",
              let responseText = payload["response_uri"] as? String, let responseURL = URL(string: responseText),
              let responseURI = try? WalletHTTP.requireHTTPS(responseURL, "The response URI"),
              responseURI.host?.lowercased() == host, responseURI.port == nil
        else { throw WalletError.untrustedVerifier("The request must be answered to its own verifier.") }

        guard let nonce = payload["nonce"] as? String, (16...256).contains(nonce.count),
              let state = payload["state"] as? String, !state.isEmpty, state.count <= 256,
              let exp = payload["exp"] as? Double, let iat = payload["iat"] as? Double
        else { throw WalletError.invalidRequest("The request is incomplete.") }
        let expiresAt = Date(timeIntervalSince1970: exp)
        guard expiresAt > now, iat <= now.timeIntervalSince1970 + clockSkew,
              exp - iat <= maxLifetime
        else { throw WalletError.invalidRequest("The request has expired.") }

        let vctValues = try adminQueryVcts(payload["dcql_query"])
        let (transactionData, purpose, tenant) = try transactionDetails(payload["transaction_data"])

        // The credential this issuer gave this device, for the requested type.
        let matching = credentials
            .filter { $0.issuer.host?.lowercased() == host && $0.issuer.port == nil && vctValues.contains($0.vct) }
            .filter { $0.expiresAt.map { $0 > now } ?? true }
            .sorted { $0.issuedAt > $1.issuedAt }
        guard let credential = matching.first else { throw WalletError.noMatchingCredential }

        return PresentationRequest(
            clientID: link.clientID, verifierHost: host, responseURI: responseURI, nonce: nonce, state: state,
            expiresAt: expiresAt, transactionData: transactionData, purpose: purpose, tenant: tenant,
            credential: credential)
    }

    /// The one DCQL query of an administrator presentation: one `dc+sd-jwt` credential under
    /// `admin`, asking for nothing but `sub` and `tenant_id`.
    private static func adminQueryVcts(_ value: Any?) throws -> [String] {
        guard let query = value as? [String: Any], query.keys.allSatisfy({ $0 == "credentials" }),
              let credentials = query["credentials"] as? [[String: Any]], credentials.count == 1,
              credentials[0]["id"] as? String == queryID,
              credentials[0]["format"] as? String == "dc+sd-jwt",
              let vcts = (credentials[0]["meta"] as? [String: Any])?["vct_values"] as? [String], !vcts.isEmpty
        else { throw WalletError.invalidRequest("The request asks for something other than the admin credential.") }
        let claims = (credentials[0]["claims"] as? [[String: Any]]) ?? []
        let paths = claims.compactMap { ($0["path"] as? [String])?.joined(separator: ".") }
        guard paths.count == claims.count, Set(paths).isSubset(of: ["sub", "tenant_id"]) else {
            throw WalletError.invalidRequest("The request asks for more than the admin credential needs.")
        }
        return vcts
    }

    private static func transactionDetails(_ value: Any?) throws -> (String, PresentationPurpose, String) {
        guard let entries = value as? [String], entries.count == 1, entries[0].count <= 4096,
              let data = Base64URL.decode(entries[0]),
              let details = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              details["type"] as? String == transactionDataType,
              details["credential_ids"] as? [String] == [queryID],
              let purpose = (details["purpose"] as? String).flatMap(PresentationPurpose.init(rawValue:))
        else { throw WalletError.invalidRequest("The request does not say what it is for.") }
        let tenant = ((details["tenant"] as? String) ?? "").prefix(200)
        return (entries[0], purpose, String(tenant))
    }
}

import Foundation

/// A credential offer as received (OpenID4VCI 1.0 section 4.1).
nonisolated struct ParsedOffer: Sendable, Equatable {
    struct TransactionCode: Sendable, Equatable {
        var inputMode: String?
        var length: Int?
        var description: String?
    }

    enum Grant: Sendable, Equatable {
        case preAuthorized(code: String, transactionCode: TransactionCode?, authorizationServer: String?)
        case authorizationCode(issuerState: String?, authorizationServer: String?)

        var authorizationServer: String? {
            switch self {
            case .preAuthorized(_, _, let server), .authorizationCode(_, let server): server
            }
        }
    }

    let credentialIssuer: String
    let configurationIds: [String]
    let grant: Grant

    var preAuthorizedCode: String? {
        if case .preAuthorized(let code, _, _) = grant { code } else { nil }
    }
    var transactionCode: TransactionCode? {
        if case .preAuthorized(_, let code, _) = grant { code } else { nil }
    }
    var authorizationServer: String? { grant.authorizationServer }
}

nonisolated enum CredentialOfferParser {
    static let schemes: Set<String> = ["openid-credential-offer", "haip-vci"]
    static let preAuthorizedGrant = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    static let maxInputLength = 8 * 1024

    /// What the offer text points to: an https URL to fetch, or the offer JSON itself.
    enum Source: Equatable {
        case reference(URL)
        case inline(Data)
    }

    /// Reads an OpenID4VCI or HAIP offer link (exactly one of `credential_offer_uri` or `credential_offer`).
    static func source(of text: String) throws -> Source {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count <= maxInputLength,
              let components = URLComponents(string: trimmed),
              let scheme = components.scheme?.lowercased(), schemes.contains(scheme)
        else { throw WalletError.notAnOffer }

        let items = components.queryItems ?? []
        let references = items.filter { $0.name == "credential_offer_uri" }
        let inlines = items.filter { $0.name == "credential_offer" }
        guard references.count + inlines.count == 1 else { throw WalletError.notAnOffer }

        if let value = references.first?.value {
            guard let url = URL(string: value) else { throw WalletError.notAnOffer }
            do { return .reference(try WalletHTTP.requireHTTPS(url, "The offer URL")) } catch { throw WalletError.notAnOffer }
        }
        guard let json = inlines.first?.value, !json.isEmpty else { throw WalletError.notAnOffer }
        return .inline(Data(json.utf8))
    }

    static func parse(json data: Data) throws -> ParsedOffer {
        guard data.count <= WalletHTTP.jsonLimit,
              let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let issuer = object["credential_issuer"] as? String,
              let ids = object["credential_configuration_ids"] as? [String], !ids.isEmpty, ids.count <= 32,
              ids.allSatisfy({ !$0.isEmpty }), Set(ids).count == ids.count
        else { throw WalletError.notAnOffer }

        guard let grants = object["grants"] as? [String: Any] else { throw WalletError.notAnOffer }
        let selectedGrant: ParsedOffer.Grant
        if let raw = grants[preAuthorizedGrant] {
            guard let grant = raw as? [String: Any],
                  let code = grant["pre-authorized_code"] as? String, !code.isEmpty,
                  grant["authorization_server"] == nil || grant["authorization_server"] is String
            else { throw WalletError.notAnOffer }
            var transactionCode: ParsedOffer.TransactionCode?
            if let raw = grant["tx_code"] {
                guard let txObject = raw as? [String: Any] else { throw WalletError.notAnOffer }
                transactionCode = .init(
                    inputMode: txObject["input_mode"] as? String,
                    length: txObject["length"] as? Int,
                    description: txObject["description"] as? String)
            }
            selectedGrant = .preAuthorized(
                code: code, transactionCode: transactionCode,
                authorizationServer: grant["authorization_server"] as? String)
        } else if let raw = grants["authorization_code"] {
            guard let grant = raw as? [String: Any],
                  grant["issuer_state"] == nil || grant["issuer_state"] is String,
                  grant["authorization_server"] == nil || grant["authorization_server"] is String
            else { throw WalletError.notAnOffer }
            let state = grant["issuer_state"] as? String
            guard state.map({ $0.utf8.count <= 8 * 1024 }) ?? true else {
                throw WalletError.notAnOffer
            }
            selectedGrant = .authorizationCode(
                issuerState: state, authorizationServer: grant["authorization_server"] as? String)
        } else {
            throw WalletError.unsupportedGrant
        }
        return ParsedOffer(credentialIssuer: issuer, configurationIds: ids, grant: selectedGrant)
    }

    /// Resolves the scanned text into an offer, fetching `credential_offer_uri` when that is the form.
    static func resolve(_ text: String, http: WalletHTTP) async throws -> ParsedOffer {
        switch try source(of: text) {
        case .inline(let data):
            return try parse(json: data)
        case .reference(let url):
            let response = try await http.send(url)
            guard response.status == 200 else { throw WalletError.network("The offer could not be fetched (HTTP \(response.status)).") }
            return try parse(json: response.data)
        }
    }
}

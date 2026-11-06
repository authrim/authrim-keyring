import CryptoKit
import Foundation

/// Answers administrator presentation requests: OpenID4VP 1.0 with a signed request object
/// (`decentralized_identifier` Client Identifier Prefix, did:web) and a `direct_post` response.
///
/// What is sent is the issuer-signed admin credential without any disclosure (the request asks
/// only for always-visible claims) and a key binding JWT signed by the credential's holder key,
/// over the request's nonce, its audience, the presentation (`sd_hash`, RFC 9901), the request's
/// `transaction_data` and the number the user typed.
nonisolated final class OpenID4VPClient: PresentationService {
    static let requestObjectType = "oauth-authz-req+jwt"
    static let matchCodeClaim = "authrim_match_code"

    private let http: WalletHTTP
    private let now: @Sendable () -> Date
    private let sign: @Sendable (String, Data, String) throws -> Data

    init(
        http: WalletHTTP = WalletHTTP(),
        now: @escaping @Sendable () -> Date = { Date() },
        sign: @escaping @Sendable (String, Data, String) throws -> Data = { tag, message, reason in
            try HolderKey.sign(tag: tag, message: message, reason: reason)
        }
    ) {
        self.http = http
        self.now = now
        self.sign = sign
    }

    func preview(link text: String, credentials: [StoredCredential]) async throws -> PresentationRequest {
        let link = try PresentationLink(text)
        guard let did = PresentationRequestValidator.did(fromClientID: link.clientID) else {
            throw WalletError.untrustedVerifier("Only requests from an Authrim issuer are answered.")
        }
        // Nothing is fetched from a host this device holds no credential from.
        guard let host = DIDWeb.host(of: did),
              credentials.contains(where: { $0.issuer.host?.lowercased() == host && $0.issuer.port == nil }),
              link.requestURI.host?.lowercased() == host, link.requestURI.port == nil
        else { throw WalletError.untrustedVerifier("This server did not issue a credential on this device.") }

        let response = try await http.send(
            link.requestURI, headers: ["Accept": "application/oauth-authz-req+jwt"], origin: link.requestURI)
        guard response.status == 200, let jwt = String(data: response.data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines), let parts = JWS.parse(jwt)
        else { throw WalletError.invalidRequest("The request could not be read (HTTP \(response.status)).") }

        // No critical header extension is understood, so a `crit` header cannot be honoured (RFC 7515 4.1.11).
        guard parts.header["alg"] as? String == "ES256",
              parts.header["typ"] as? String == Self.requestObjectType,
              parts.header["crit"] == nil,
              let keyID = parts.header["kid"] as? String
        else { throw WalletError.untrustedVerifier("The request is not signed as an Authrim request.") }
        let key = try await DIDWeb.assertionKey(keyID: keyID, did: did, http: http)
        guard let cryptoKey = key.cryptoKey, JWS.verifyES256(parts, with: cryptoKey) else {
            throw WalletError.untrustedVerifier("The request signature is not valid.")
        }
        return try PresentationRequestValidator.validate(
            payload: parts.payload, link: link, credentials: credentials, now: now())
    }

    func present(_ request: PresentationRequest, matchCode: String) async throws {
        guard matchCode.count == 2, matchCode.allSatisfy(\.isASCIIDigit) else {
            throw WalletError.invalidRequest("Enter the two digits shown in the admin console.")
        }
        try checkStillValid(request)
        let presentation = try await signPresentation(request, matchCode: matchCode)
        // Face ID or the passcode may have taken a while: nothing is sent once either has run out.
        try checkStillValid(request)
        let vpToken = try JSONSerialization.data(withJSONObject: [PresentationRequestValidator.queryID: [presentation]])
        let body = WalletHTTP.formBody([
            ("vp_token", String(decoding: vpToken, as: UTF8.self)),
            ("state", request.state),
        ])
        let response = try await http.send(
            request.responseURI, method: "POST",
            headers: ["Content-Type": "application/x-www-form-urlencoded"], body: body,
            origin: request.responseURI)
        guard response.isSuccess else {
            let object = (try? JSONSerialization.jsonObject(with: response.data)) as? [String: Any]
            throw WalletError.presentationRefused(
                (object?["error_description"] as? String) ?? response.errorCode ?? "HTTP \(response.status)")
        }
    }

    private func checkStillValid(_ request: PresentationRequest) throws {
        let now = now()
        guard request.expiresAt > now else { throw WalletError.invalidRequest("The request has expired.") }
        if let expiry = request.credential.expiresAt, expiry <= now {
            throw WalletError.noMatchingCredential
        }
    }

    /// Signs the key binding. `@concurrent` keeps it off the main actor: the Secure Enclave call
    /// blocks while Face ID / the passcode prompt is up.
    @concurrent
    private func signPresentation(_ request: PresentationRequest, matchCode: String) async throws -> String {
        try Self.presentation(
            for: request, matchCode: matchCode, issuedAt: now(),
            sign: { message in
                try self.sign(
                    request.credential.keyTag, message,
                    String(localized: "Approve the request from the Authrim admin console"))
            })
    }

    /// `<issuer JWT>~<KB-JWT>`: the credential with no disclosures, bound to this request.
    static func presentation(
        for request: PresentationRequest, matchCode: String, issuedAt: Date, sign: (Data) throws -> Data
    ) throws -> String {
        let credential = try ParsedSDJWT(request.credential.sdJwt)
        let prefix = credential.issuerJWT + "~"
        let payload: [String: Any] = [
            "iat": Int(issuedAt.timeIntervalSince1970),
            "aud": request.clientID,
            "nonce": request.nonce,
            "sd_hash": sha256(prefix),
            "transaction_data_hashes": [sha256(request.transactionData)],
            "transaction_data_hashes_alg": "sha-256",
            matchCodeClaim: matchCode,
        ]
        let keyBinding = try JWS.make(header: ["alg": "ES256", "typ": "kb+jwt"], payload: payload, sign: sign)
        return prefix + keyBinding
    }

    static func sha256(_ text: String) -> String {
        Base64URL.encode(Data(SHA256.hash(data: Data(text.utf8))))
    }
}

private extension Character {
    var isASCIIDigit: Bool { ("0"..."9").contains(self) }
}

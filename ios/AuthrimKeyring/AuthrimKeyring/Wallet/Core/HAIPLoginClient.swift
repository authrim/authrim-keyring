import CryptoKit
import Foundation
import Security

/// Answers the Authrim admin console's sign-in request (OpenID4VP 1.0, HAIP 1.0): a request object
/// signed with a certificate that chains to a pinned Authrim root, the `x509_hash` client identifier,
/// a `direct_post.jwt` response encrypted with ECDH-ES, and a same-device return to the console.
///
/// What is sent is the issuer-signed credential with no disclosure and a key binding JWT signed by
/// the holder key over this request's nonce and client identifier. Nothing is fetched from a host
/// this device holds no credential from, and nothing is answered unless the request chain is trusted.
nonisolated final class HAIPLoginClient: Sendable {
    private let http: WalletHTTP
    private let roots: [Data]
    private let consoleHosts: Set<String>
    private let adminVCTs: Set<String>
    private let now: @Sendable () -> Date
    private let sign: @Sendable (String, Data, String) throws -> Data

    init(
        roots: [Data], consoleHosts: Set<String> = [], adminVCTs: Set<String> = [AuthrimCATrustSource.adminVCT],
        http: WalletHTTP = WalletHTTP(),
        now: @escaping @Sendable () -> Date = { Date() },
        sign: @escaping @Sendable (String, Data, String) throws -> Data = { tag, message, reason in
            try HolderKey.sign(tag: tag, message: message, reason: reason)
        }
    ) {
        self.roots = roots
        self.consoleHosts = Set(consoleHosts.map { $0.lowercased() })
        self.adminVCTs = adminVCTs
        self.http = http
        self.now = now
        self.sign = sign
    }

    // MARK: Request

    func preview(link text: String, credentials: [StoredCredential]) async throws -> HAIPLoginRequest {
        let link = try HAIPLoginLink(text)
        guard !roots.isEmpty else { throw WalletError.unsupportedIssuerCertificateTrust }
        guard let host = link.requestURI.host?.lowercased(),
              credentials.contains(where: { $0.issuer.host?.lowercased() == host && $0.issuer.port == nil && adminVCTs.contains($0.vct) })
        else { throw WalletError.untrustedVerifier("This server did not issue a credential on this device.") }
        let response = try await http.send(
            link.requestURI, headers: ["Accept": "application/oauth-authz-req+jwt"], origin: link.requestURI)
        guard response.status == 200, let jwt = String(data: response.data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines), let parts = JWS.parse(jwt)
        else { throw WalletError.invalidRequest("The request could not be read (HTTP \(response.status)).") }
        try verifySignature(parts, link: link, host: host)
        return try HAIPLoginRequestValidator.validate(
            payload: parts.payload, link: link, verifierHost: host, credentials: credentials,
            adminVCTs: adminVCTs, now: now())
    }

    /// Header, certificate chain, `x509_hash` binding, verifier name and signature.
    private func verifySignature(_ parts: JWS.Parts, link: HAIPLoginLink, host: String) throws {
        let untrusted = WalletError.untrustedVerifier("The request is not signed by an Authrim verifier.")
        guard parts.header["alg"] as? String == "ES256", parts.header["typ"] as? String == "oauth-authz-req+jwt",
              parts.header["crit"] == nil, let encoded = parts.header["x5c"] as? [String], (1...8).contains(encoded.count)
        else { throw untrusted }
        let chain = encoded.compactMap { Data(base64Encoded: $0) }
        guard chain.count == encoded.count, let leaf = chain.first else { throw untrusted }
        // The identifier is bound to the leaf, so a request cannot be re-signed by another certificate.
        let hash = Base64URL.encode(Data(SHA256.hash(data: leaf)))
        guard link.clientID == HAIPLoginLink.clientIDPrefix + hash else { throw untrusted }
        guard CertificateChainTrust.isTrusted(chain, roots: roots, now: now()),
              let hostURL = URL(string: "https://" + host), IssuerCertificateNames.matches(issuer: hostURL, in: leaf, dnsOnly: true),
              let certificate = SecCertificateCreateWithData(nil, leaf as CFData),
              let key = SecCertificateCopyKey(certificate),
              let point = SecKeyCopyExternalRepresentation(key, nil) as Data?,
              let jwk = PublicJWK(x963: point), let verifying = jwk.cryptoKey,
              JWS.verifyES256(parts, with: verifying)
        else { throw untrusted }
    }

    // MARK: Response

    /// Signs, encrypts and posts the response; returns the console URL to open in the browser.
    func present(_ request: HAIPLoginRequest) async throws -> URL {
        try checkStillValid(request)
        let presentation = try await signPresentation(request)
        try checkStillValid(request)
        let payload: [String: Any] = ["vp_token": [request.queryID: [presentation]], "state": request.state]
        let jwe = try WalletJWE.encrypt(
            try JSONSerialization.data(withJSONObject: payload), to: request.encryptionKey,
            kid: request.encryptionKeyID, enc: request.enc)
        let response = try await http.send(
            request.responseURI, method: "POST",
            headers: ["Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"],
            body: WalletHTTP.formBody([("response", jwe)]), origin: request.responseURI)
        guard response.isSuccess else {
            let object = (try? JSONSerialization.jsonObject(with: response.data)) as? [String: Any]
            throw WalletError.presentationRefused((object?["error_description"] as? String) ?? response.errorCode ?? "HTTP \(response.status)")
        }
        guard let object = (try? JSONSerialization.jsonObject(with: response.data)) as? [String: Any],
              let text = object["redirect_uri"] as? String, let url = URL(string: text),
              let checked = try? WalletHTTP.requireHTTPS(url, "The return address"),
              let host = checked.host?.lowercased(), checked.fragment == nil,
              checked.port == nil, host == request.verifierHost || consoleHosts.contains(host)
        else { throw WalletError.untrustedVerifier("The verifier returned an address Keyring does not open.") }
        return checked
    }

    private func checkStillValid(_ request: HAIPLoginRequest) throws {
        let now = now()
        guard request.expiresAt > now else { throw WalletError.invalidRequest("The request has expired.") }
        if let expiry = request.credential.expiresAt, expiry <= now { throw WalletError.noMatchingCredential }
    }

    @concurrent
    private func signPresentation(_ request: HAIPLoginRequest) async throws -> String {
        try Self.presentation(for: request, issuedAt: now()) { message in
            try self.sign(request.credential.keyTag, message,
                          String(localized: "Sign in to the Authrim admin console"))
        }
    }

    /// `<issuer JWT>~<KB-JWT>`: the credential with no disclosures, bound to this request.
    static func presentation(for request: HAIPLoginRequest, issuedAt: Date, sign: (Data) throws -> Data) throws -> String {
        let credential = try ParsedSDJWT(request.credential.sdJwt)
        let prefix = credential.issuerJWT + "~"
        let payload: [String: Any] = [
            "iat": Int(issuedAt.timeIntervalSince1970), "aud": request.clientID, "nonce": request.nonce,
            "sd_hash": OpenID4VPClient.sha256(prefix),
        ]
        return prefix + (try JWS.make(header: ["alg": "ES256", "typ": "kb+jwt"], payload: payload, sign: sign))
    }
}

/// X.509 path validation to anchors the build pins, with no network and no anchor taken from the chain.
nonisolated enum CertificateChainTrust {
    static func isTrusted(_ chainDER: [Data], roots rootsDER: [Data], now: Date) -> Bool {
        guard (1...8).contains(chainDER.count), !rootsDER.isEmpty,
              !chainDER.contains(where: rootsDER.contains) else { return false }
        let chain = chainDER.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        let roots = rootsDER.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        guard chain.count == chainDER.count, roots.count == rootsDER.count else { return false }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(chain as CFArray, SecPolicyCreateBasicX509(), &trust) == errSecSuccess,
              let trust,
              SecTrustSetAnchorCertificates(trust, roots as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
              SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
              SecTrustSetVerifyDate(trust, now as CFDate) == errSecSuccess,
              SecTrustEvaluateWithError(trust, nil), SecTrustGetCertificateCount(trust) >= 2
        else { return false }
        return true
    }
}

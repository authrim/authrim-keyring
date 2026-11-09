import Foundation
import Security

nonisolated struct WalletClientAttestation: Sendable {
    let jwt: String
    let clientID: String
}

nonisolated protocol WalletAttestationProvider: Sendable {
    func supports(issuer: URL) -> Bool
    func attestation(for clientKey: PublicJWK, issuer: URL) async throws -> WalletClientAttestation
}

nonisolated protocol WalletAttestationTrustSource: Sendable {
    func trustedRoots(for attestation: String, issuer: URL) async throws -> [Data]
}

nonisolated enum WalletAttestationValidationError: Error, Equatable {
    case malformedJWT
    case unsupportedHeader
    case untrustedCertificate
    case invalidSignature
    case invalidTime
    case wrongProvider
    case wrongClientKey
    case invalidClientID
}

/// Verifies a Wallet Instance Attestation before its client ID is used in an OAuth PoP.
/// The caller supplies an independent CA anchor; the WIA's x5c is never used as that anchor.
nonisolated enum WalletAttestationVerifier {
    static func validate(
        _ jwt: String, clientKey: PublicJWK, providerIssuer: URL,
        trustedRootDER: [Data], now: Date
    ) throws -> WalletClientAttestation {
        guard jwt.utf8.count <= 64 * 1024, let parts = JWS.parse(jwt) else {
            throw WalletAttestationValidationError.malformedJWT
        }
        guard parts.header["typ"] as? String == "oauth-client-attestation+jwt",
              parts.header["alg"] as? String == "ES256",
              parts.header["crit"] == nil, parts.header["b64"] == nil,
              let chain = parts.header["x5c"] as? [String], (1...8).contains(chain.count)
        else { throw WalletAttestationValidationError.unsupportedHeader }
        let certificateDER = chain.compactMap(AttestationCertificateCoding.decode)
        guard certificateDER.count == chain.count, !trustedRootDER.isEmpty,
              !certificateDER.contains(where: trustedRootDER.contains),
              let chainCertificates = makeCertificates(certificateDER),
              let anchors = makeCertificates(trustedRootDER)
        else { throw WalletAttestationValidationError.untrustedCertificate }

        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(chainCertificates as CFArray, SecPolicyCreateBasicX509(), &trust) == errSecSuccess,
              let trust,
              SecTrustSetAnchorCertificates(trust, anchors as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
              SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
              SecTrustSetVerifyDate(trust, now as CFDate) == errSecSuccess,
              SecTrustEvaluateWithError(trust, nil), SecTrustGetCertificateCount(trust) >= 2
        else { throw WalletAttestationValidationError.untrustedCertificate }

        guard let signingKey = SecCertificateCopyKey(chainCertificates[0]),
              let point = SecKeyCopyExternalRepresentation(signingKey, nil) as Data?,
              let signingJWK = PublicJWK(x963: point),
              let publicKey = signingJWK.cryptoKey,
              JWS.verifyES256(parts, with: publicKey)
        else { throw WalletAttestationValidationError.invalidSignature }

        guard parts.payload["iss"] as? String == providerIssuer.absoluteString else {
            throw WalletAttestationValidationError.wrongProvider
        }
        guard let clientID = parts.payload["sub"] as? String,
              !clientID.isEmpty, clientID.utf8.count <= 256,
              clientID.utf8.allSatisfy({ (0x21...0x7e).contains($0) })
        else { throw WalletAttestationValidationError.invalidClientID }
        guard let expiresAt = integerClaim(parts.payload["exp"]),
              expiresAt >= 0, TimeInterval(expiresAt) > now.timeIntervalSince1970
        else { throw WalletAttestationValidationError.invalidTime }
        // The OID4VCI 1.0 referenced attestation draft makes iat and nbf optional. If
        // present, both must still be well-formed and valid at the current time.
        if let rawIssuedAt = parts.payload["iat"] {
            guard let issuedAt = integerClaim(rawIssuedAt), issuedAt >= 0,
                  expiresAt > issuedAt,
                  TimeInterval(issuedAt) <= now.timeIntervalSince1970 + 60
            else { throw WalletAttestationValidationError.invalidTime }
        }
        if let rawNotBefore = parts.payload["nbf"] {
            guard let notBefore = integerClaim(rawNotBefore), notBefore >= 0,
                  TimeInterval(notBefore) <= now.timeIntervalSince1970 + 60
            else { throw WalletAttestationValidationError.invalidTime }
        }
        guard let confirmation = parts.payload["cnf"] as? [String: Any],
              let jwkObject = confirmation["jwk"] as? [String: Any], jwkObject["d"] == nil,
              let confirmedKey = PublicJWK(from: jwkObject),
              confirmedKey.cryptoKey != nil, confirmedKey.isSameKey(as: clientKey)
        else { throw WalletAttestationValidationError.wrongClientKey }
        return WalletClientAttestation(jwt: jwt, clientID: clientID)
    }

    private static func makeCertificates(_ encoded: [Data]) -> [SecCertificate]? {
        let result = encoded.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        return result.count == encoded.count ? result : nil
    }

    private static func integerClaim(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue == Double(number.int64Value)
        else { return nil }
        return number.int64Value
    }
}

/// Strict standard Base64 decoding, with or without terminal padding. The EUDI trust validator
/// returns an unpadded Base64 DER anchor, while x5c certificates are commonly padded.
private nonisolated enum AttestationCertificateCoding {
    static func decode(_ encoded: String) -> Data? {
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

/// Uses the public EUDI mock provider only for `https://issuer.eudiw.dev` interoperability tests.
/// The JWK route does not verify iOS platform attestation and must not be used as production WIA.
nonisolated struct EUDITestWalletAttestationProvider: WalletAttestationProvider, WalletAttestationTrustSource {
    private static let issuerIdentifier = "https://issuer.eudiw.dev"
    private static let providerOrigin = URL(string: "https://wallet-provider.eudiw.dev")!
    private static let attestationEndpoint = URL(string: "https://wallet-provider.eudiw.dev/wallet-instance-attestation/jwk")!
    private static let validatorOrigin = URL(string: "https://trust-validator.eudiw.dev")!
    private static let trustEndpoint = URL(string: "https://trust-validator.eudiw.dev/trust")!

    private let http: WalletHTTP

    init(http: WalletHTTP = WalletHTTP()) {
        self.http = http
    }

    func supports(issuer: URL) -> Bool {
        issuer.absoluteString == Self.issuerIdentifier
    }

    func attestation(for clientKey: PublicJWK, issuer: URL) async throws -> WalletClientAttestation {
        try requireTestIssuer(issuer)
        guard clientKey.cryptoKey != nil else {
            throw WalletError.keyUnavailable("The wallet client public key is invalid.")
        }
        var providerJWK = clientKey.proofMembers
        providerJWK["alg"] = "ES256"
        let body = try JSONSerialization.data(withJSONObject: ["jwk": providerJWK])
        let response = try await http.send(
            Self.attestationEndpoint, method: "POST",
            headers: ["Content-Type": "application/json"], body: body,
            origin: Self.providerOrigin)
        guard response.status == 200,
              let object = (try? JSONSerialization.jsonObject(with: response.data)) as? [String: Any],
              let jwt = object["walletInstanceAttestation"] as? String
        else { throw WalletError.network("The EUDI test wallet provider did not issue a wallet attestation.") }

        let roots = try await trustedRoots(for: jwt, issuer: issuer)
        do {
            return try WalletAttestationVerifier.validate(
                jwt, clientKey: clientKey, providerIssuer: Self.providerOrigin,
                trustedRootDER: roots, now: .now)
        } catch {
            throw WalletError.invalidIssuer("The EUDI test wallet attestation did not validate.")
        }
    }

    func trustedRoots(for attestation: String, issuer: URL) async throws -> [Data] {
        try requireTestIssuer(issuer)
        guard attestation.utf8.count <= 64 * 1024, let parts = JWS.parse(attestation),
              parts.header["typ"] as? String == "oauth-client-attestation+jwt",
              parts.header["alg"] as? String == "ES256",
              let chain = parts.header["x5c"] as? [String], (1...8).contains(chain.count)
        else { throw WalletError.invalidIssuer("The wallet attestation certificate chain is invalid.") }
        let certificateDER = chain.compactMap(AttestationCertificateCoding.decode)
        guard certificateDER.count == chain.count else {
            throw WalletError.invalidIssuer("The wallet attestation certificate chain is invalid.")
        }

        // Only public certificate bytes cross this boundary. The remote validator decides
        // whether the signing chain is trusted for WalletProviderAttestation.
        let body = try JSONSerialization.data(withJSONObject: [
            "chain": chain, "verificationContext": "WalletProviderAttestation",
        ])
        let response = try await http.send(
            Self.trustEndpoint, method: "POST",
            headers: ["Content-Type": "application/json"], body: body,
            origin: Self.validatorOrigin)
        guard response.status == 200,
              let object = (try? JSONSerialization.jsonObject(with: response.data)) as? [String: Any],
              object["trusted"] as? Bool == true,
              let encodedAnchor = object["trustAnchor"] as? String,
              let anchor = AttestationCertificateCoding.decode(encodedAnchor),
              !certificateDER.contains(anchor),
              SecCertificateCreateWithData(nil, anchor as CFData) != nil
        else { throw WalletError.invalidIssuer("The EUDI test wallet provider certificate is not trusted.") }
        return [anchor]
    }

    private func requireTestIssuer(_ issuer: URL) throws {
        guard supports(issuer: issuer) else { throw WalletError.unsupportedKeyAttestation }
    }
}

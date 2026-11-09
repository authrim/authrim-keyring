import Foundation
import Security

/// The assurance values an issuer accepts for the holder key. An empty set imposes no constraint
/// for that claim; it does not make a key attestation optional.
nonisolated struct KeyAttestationRequirements: Equatable, Sendable {
    let acceptedKeyStorage: Set<String>
    let acceptedUserAuthentication: Set<String>

    init(acceptedKeyStorage: Set<String>, acceptedUserAuthentication: Set<String>) {
        self.acceptedKeyStorage = acceptedKeyStorage
        self.acceptedUserAuthentication = acceptedUserAuthentication
    }
}

/// A wallet-provider service can produce the signed attestation. The app cannot certify the
/// security properties of its own Secure Enclave key merely by signing with that key.
nonisolated protocol KeyAttestationProvider: Sendable {
    func supports(issuer: URL) -> Bool
    func attestation(for holderKey: PublicJWK, nonce: String?, issuer: URL) async throws -> String
}

/// Trust roots are selected by wallet policy for the requesting issuer. They must not be taken
/// from an untrusted `x5c` header or from the attestation provider's response alone.
nonisolated protocol KeyAttestationTrustSource: Sendable {
    func trustedRoots(for attestation: String, issuer: URL) async throws -> [Data]
}

nonisolated enum KeyAttestationValidationError: Error, Equatable {
    case missingTrustAnchor
    case malformedJWT
    case unsupportedHeader
    case untrustedCertificate
    case invalidSignature
    case invalidTime
    case wrongNonce
    case wrongHolderKey
    case insufficientAssurance
}

/// Checks an OpenID4VCI Appendix D key attestation before including it in a credential proof.
/// Trust anchors must be configured by the wallet ecosystem, independently of the attestation
/// provider or credential issuer. The verifier checks signed claims; it cannot establish that a
/// provider's `iso_18045_high` assertion is true without a corresponding trust policy/audit.
nonisolated enum KeyAttestationVerifier {
    static func validate(
        _ jwt: String,
        holderKey: PublicJWK,
        nonce: String?,
        requirements: KeyAttestationRequirements,
        trustedRootDER: [Data],
        now: Date
    ) throws -> String {
        guard !trustedRootDER.isEmpty else { throw KeyAttestationValidationError.missingTrustAnchor }
        guard jwt.utf8.count <= 64 * 1024, let parts = JWS.parse(jwt) else {
            throw KeyAttestationValidationError.malformedJWT
        }
        guard parts.header["typ"] as? String == "key-attestation+jwt",
              parts.header["alg"] as? String == "ES256",
              parts.header["crit"] == nil, parts.header["b64"] == nil,
              let encodedChain = parts.header["x5c"] as? [String],
              (1...8).contains(encodedChain.count)
        else { throw KeyAttestationValidationError.unsupportedHeader }

        let certificateDER = try encodedChain.map { encoded -> Data in
            guard encoded.utf8.count <= 16 * 1024,
                  let der = Data(base64Encoded: encoded), !der.isEmpty else {
                throw KeyAttestationValidationError.untrustedCertificate
            }
            return der
        }
        try validateCertificateChain(certificateDER, trustedRootDER: trustedRootDER, now: now)
        guard let leaf = SecCertificateCreateWithData(nil, certificateDER[0] as CFData),
              let publicKey = SecCertificateCopyKey(leaf),
              let point = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?,
              let signingJWK = PublicJWK(x963: point),
              let signingKey = signingJWK.cryptoKey,
              JWS.verifyES256(parts, with: signingKey)
        else { throw KeyAttestationValidationError.invalidSignature }

        guard let issuedAt = integerClaim(parts.payload["iat"]),
              let expiresAt = integerClaim(parts.payload["exp"]),
              issuedAt >= 0, expiresAt > issuedAt,
              TimeInterval(issuedAt) <= now.timeIntervalSince1970 + 60,
              TimeInterval(expiresAt) > now.timeIntervalSince1970
        else { throw KeyAttestationValidationError.invalidTime }
        if let nonce, parts.payload["nonce"] as? String != nonce {
            throw KeyAttestationValidationError.wrongNonce
        }

        guard holderKey.cryptoKey != nil,
              let attestedKeys = parts.payload["attested_keys"] as? [[String: Any]],
              (1...32).contains(attestedKeys.count),
              attestedKeys.compactMap({ PublicJWK(from: $0) })
                .filter({ $0.isSameKey(as: holderKey) }).count == 1
        else { throw KeyAttestationValidationError.wrongHolderKey }

        try requireAssurance(
            parts.payload["key_storage"], accepted: requirements.acceptedKeyStorage)
        try requireAssurance(
            parts.payload["user_authentication"], accepted: requirements.acceptedUserAuthentication)
        return jwt
    }

    private static func integerClaim(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue == Double(number.int64Value)
        else { return nil }
        return number.int64Value
    }

    private static func requireAssurance(_ value: Any?, accepted: Set<String>) throws {
        guard !accepted.isEmpty else { return }
        guard let asserted = value as? [String], !asserted.isEmpty,
              asserted.contains(where: accepted.contains)
        else { throw KeyAttestationValidationError.insufficientAssurance }
    }

    private static func validateCertificateChain(
        _ certificateDER: [Data], trustedRootDER: [Data], now: Date
    ) throws {
        // HAIP requires a non-self-signed signing certificate and excludes the trust anchor
        // from the attestation's x5c. A trust anchor sent by the provider is not trusted input.
        let certificates = certificateDER.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        let anchors = trustedRootDER.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        guard !certificateDER.contains(where: trustedRootDER.contains),
              certificates.count == certificateDER.count,
              anchors.count == trustedRootDER.count
        else { throw KeyAttestationValidationError.untrustedCertificate }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(certificates as CFArray, SecPolicyCreateBasicX509(), &trust) == errSecSuccess,
              let trust,
              SecTrustSetAnchorCertificates(trust, anchors as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
              SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
              SecTrustSetVerifyDate(trust, now as CFDate) == errSecSuccess,
              SecTrustEvaluateWithError(trust, nil),
              SecTrustGetCertificateCount(trust) >= 2
        else { throw KeyAttestationValidationError.untrustedCertificate }
    }
}

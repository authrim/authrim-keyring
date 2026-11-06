import Foundation

/// Renewing an admin credential with the holder key it already has.
///
/// The Authrim admin console registers a Keyring holder key (not a credential) as an admin's
/// second factor. When it offers a new credential, the offer link names the thumbprints of the
/// admin's registered keys (`authrim_renew_holder_jkt`, comma-separated RFC 7638 thumbprints). If
/// this device holds a credential of the same issuer and type bound to one of those keys, Keyring
/// signs the new proof with that key instead of creating one, so the second factor carries over.
///
/// The hint only ever selects a key this device already uses for that very issuer and credential
/// type: a link naming another key, or a key of another issuer, changes nothing.
nonisolated enum HolderKeyRenewal {
    static let hintParameter = "authrim_renew_holder_jkt"
    /// More would not fit an admin's factors; a longer list is ignored as malformed.
    static let maxHints = 8

    /// The thumbprints the offer link names, or none. Malformed values are dropped.
    static func hints(in offerText: String) -> Set<String> {
        guard let components = URLComponents(string: offerText.trimmingCharacters(in: .whitespacesAndNewlines))
        else { return [] }
        let values = (components.queryItems ?? []).filter { $0.name == hintParameter }
        guard values.count == 1, let raw = values[0].value else { return [] }
        let parts = raw.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        guard parts.count <= maxHints else { return [] }
        return Set(parts.filter { $0.wholeMatch(of: /[A-Za-z0-9_-]{43}/) != nil })
    }

    /// The holder key the credential is bound to (`cnf.jwk` of its issuer-signed JWT).
    static func holderKey(of credential: StoredCredential) -> PublicJWK? {
        guard let cnf = issuerPayload(of: credential.sdJwt)?["cnf"] as? [String: Any],
              let jwk = cnf["jwk"] as? [String: Any]
        else { return nil }
        return PublicJWK(from: jwk)
    }

    /// The administrator a credential names (`sub` of its issuer-signed JWT).
    static func subject(ofSDJWT sdJwt: String) -> String? {
        issuerPayload(of: sdJwt)?["sub"] as? String
    }

    /// Whether `issued` names the same administrator as the credential it renews. The offer link
    /// that names the key is not authenticated: a credential of someone else bound to this
    /// device's key is refused, so it can never stand in for the admin's own.
    static func isSameAdministrator(_ issued: String, as renewed: StoredCredential) -> Bool {
        guard let subject = subject(ofSDJWT: issued), let earlier = self.subject(ofSDJWT: renewed.sdJwt)
        else { return false }
        // Byte for byte: Swift's `==` treats canonically equivalent strings as equal, JWT
        // identifiers are compared as they are (RFC 7519 section 2).
        return subject.utf8.elementsEqual(earlier.utf8)
    }

    private static func issuerPayload(of sdJwt: String) -> [String: Any]? {
        guard let jwt = sdJwt.split(separator: "~", maxSplits: 1).first else { return nil }
        let segments = jwt.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3, let data = Base64URL.decode(String(segments[1])) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    /// base64url RFC 7638 thumbprint of the credential's holder key, as the server writes it.
    static func thumbprint(of credential: StoredCredential) -> String? {
        holderKey(of: credential).map { Base64URL.encode($0.thumbprint) }
    }

    /// The newest stored credential of this issuer and type whose key the offer names, if any.
    static func renewable(
        from credentials: [StoredCredential], issuer: URL, vct: String, hints: Set<String>
    ) -> StoredCredential? {
        guard !hints.isEmpty else { return nil }
        return credentials
            .filter { $0.issuer == issuer && $0.vct == vct }
            .sorted { $0.issuedAt > $1.issuedAt }
            .first { thumbprint(of: $0).map(hints.contains) ?? false }
    }
}

/// A holder key that already exists in the Secure Enclave (or the simulator's software store),
/// used to sign the proof of a renewed credential. Signing asks for Face ID or the passcode.
nonisolated struct ExistingHolderKey: HolderSigning {
    let tag: String
    let publicJWK: PublicJWK
    let reason: String

    func sign(_ message: Data) throws -> Data {
        try HolderKey.sign(tag: tag, message: message, reason: reason)
    }
}

/// Holder keys that a renewal is using right now, so deleting the credential it renews keeps the
/// key until the new credential is stored (or the renewal gave up).
nonisolated final class HolderKeyReservations: @unchecked Sendable {
    static let shared = HolderKeyReservations()

    private let lock = NSLock()
    private var counts: [String: Int] = [:]

    func reserve(_ tag: String) {
        lock.withLock { counts[tag, default: 0] += 1 }
    }

    func release(_ tag: String) {
        lock.withLock {
            let remaining = (counts[tag] ?? 1) - 1
            counts[tag] = remaining > 0 ? remaining : nil
        }
    }

    func isReserved(_ tag: String) -> Bool {
        lock.withLock { counts[tag] != nil }
    }
}

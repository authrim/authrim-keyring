import Foundation

/// Resolves the signing key of a `did:web` verifier: the DID document at
/// `https://<host>/.well-known/did.json`, fetched with the wallet's https-only, no-redirect client.
///
/// Only host-level DIDs (`did:web:example.com`, no path, no port) are accepted, because the wallet
/// compares that host with the host of the credential's issuer.
nonisolated enum DIDWeb {
    /// `did:web:<host>` for a lower-case public host name, or nil.
    static func host(of did: String) -> String? {
        let prefix = "did:web:"
        guard did.hasPrefix(prefix) else { return nil }
        let host = String(did.dropFirst(prefix.count))
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789.-")
        guard !host.isEmpty, host.count <= 253, host.unicodeScalars.allSatisfy(allowed.contains),
              !host.hasPrefix("."), !host.hasSuffix("."), WalletHTTP.isPublicHost(host)
        else { return nil }
        return host
    }

    static func documentURL(for did: String) -> URL? {
        guard let host = host(of: did) else { return nil }
        return URL(string: "https://\(host)/.well-known/did.json")
    }

    /// The P-256 key the DID document lists under `keyID` (a DID URL `did#fragment`) as an
    /// assertion method of that same DID.
    static func assertionKey(keyID: String, did: String, http: WalletHTTP) async throws -> PublicJWK {
        guard keyID.hasPrefix(did + "#"), let url = documentURL(for: did) else {
            throw WalletError.untrustedVerifier("The request is not signed with a key of its verifier.")
        }
        let document = try await http.getJSON(url, origin: url)
        guard (document["id"] as? String) == did else {
            throw WalletError.untrustedVerifier("The DID document belongs to another identifier.")
        }
        let methods = (document["verificationMethod"] as? [[String: Any]]) ?? []
        let assertion = (document["assertionMethod"] as? [Any]) ?? []
        let asserted = Set(assertion.compactMap { entry -> String? in
            if let reference = entry as? String { return absolute(reference, did: did) }
            if let method = entry as? [String: Any], let id = method["id"] as? String { return absolute(id, did: did) }
            return nil
        })
        let embedded = assertion.compactMap { $0 as? [String: Any] }
        let matches = (methods + embedded).filter { absolute(($0["id"] as? String) ?? "", did: did) == keyID }
        guard asserted.contains(keyID), let method = matches.first,
              (method["controller"] as? String).map({ $0 == did }) ?? true,
              let jwkObject = method["publicKeyJwk"] as? [String: Any],
              let key = PublicJWK(from: jwkObject), key.cryptoKey != nil
        else { throw WalletError.untrustedVerifier("The verifier does not publish this signing key.") }
        return key
    }

    private static func absolute(_ reference: String, did: String) -> String {
        reference.hasPrefix("#") ? did + reference : reference
    }
}

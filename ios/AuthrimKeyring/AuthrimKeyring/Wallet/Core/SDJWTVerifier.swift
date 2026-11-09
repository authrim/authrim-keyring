import CryptoKit
import Foundation

/// An issued SD-JWT VC split into its issuer-signed JWT and disclosures.
nonisolated struct ParsedSDJWT: Sendable {
    let issuerJWT: String
    let disclosures: [String]

    /// `<issuer-jwt>~<disclosure>~...~`: a credential straight from issuance has no key binding JWT, so the
    /// text must end with `~`.
    init(_ text: String) throws {
        let pieces = text.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
        guard pieces.count >= 2, pieces.last == "", !pieces[0].isEmpty,
              !pieces.dropFirst().dropLast().contains("")
        else { throw WalletError.invalidCredential("The credential is not a well-formed SD-JWT.") }
        issuerJWT = pieces[0]
        disclosures = Array(pieces.dropFirst().dropLast())
    }
}

nonisolated struct VerifiedCredential: Sendable {
    let issuedAt: Date?
    let expiresAt: Date
    /// Plain and disclosed claims as display strings.
    let claims: [String: String]
}

nonisolated enum SDJWTVerifier {
    /// Claims that are protocol plumbing, not shown to the user.
    static let hiddenClaims: Set<String> = ["_sd", "_sd_alg", "cnf", "status", "iss", "vct", "iat", "exp"]
    static let maxIssuedAtSkew: TimeInterval = 300
    static let maxDisclosures = 64
    static let maxDisplayedClaims = 64
    static let maxClaimValueLength = 1_000
    /// Claims that must stay in the signed payload and never be selectively disclosed (SD-JWT VC 3.2.2.2).
    static let neverDisclosed: Set<String> = ["iss", "nbf", "exp", "iat", "cnf", "vct", "status", "_sd", "_sd_alg", "..."]

    /// The `kid` the issuer JWT header names, to pick the key from the issuer's JWKS.
    static func keyID(of parsed: ParsedSDJWT) throws -> String {
        guard let parts = JWS.parse(parsed.issuerJWT), let kid = parts.header["kid"] as? String, !kid.isEmpty else {
            throw WalletError.invalidCredential("The credential names no signing key.")
        }
        return kid
    }

    /// Verifies the credential against everything the wallet knows. Throws `invalidCredential` otherwise.
    static func verify(
        _ parsed: ParsedSDJWT, issuerKey: PublicJWK, expectedIssuer: String, expectedVct: String,
        holderKey: PublicJWK, now: Date
    ) throws -> VerifiedCredential {
        guard let parts = JWS.parse(parsed.issuerJWT) else { throw fail("The credential is not a valid JWT.") }
        guard (parts.header["alg"] as? String) == "ES256" else { throw fail("The credential is not signed with ES256.") }
        guard (parts.header["typ"] as? String) == "dc+sd-jwt" else { throw fail("The credential has the wrong type.") }
        // No critical header extension is understood, so a `crit` header cannot be honoured (RFC 7515 4.1.11).
        guard parts.header["crit"] == nil else { throw fail("The credential needs an unsupported extension.") }
        guard (issuerKey.alg ?? "ES256") == "ES256", issuerKey.use == nil || issuerKey.use == "sig",
              let key = issuerKey.cryptoKey, JWS.verifyES256(parts, with: key)
        else { throw fail("The issuer signature is not valid.") }

        let payload = parts.payload
        guard (payload["iss"] as? String) == expectedIssuer else { throw fail("The credential comes from a different issuer.") }
        guard (payload["vct"] as? String) == expectedVct else { throw fail("The credential is not the type that was offered.") }

        guard let cnf = payload["cnf"] as? [String: Any], let jwkObject = cnf["jwk"] as? [String: Any],
              let boundKey = PublicJWK(from: jwkObject), boundKey.isSameKey(as: holderKey)
        else { throw fail("The credential is not bound to this device's key.") }

        guard let exp = number(payload["exp"]), Date(timeIntervalSince1970: exp) > now else {
            throw fail("The credential has already expired.")
        }
        var issuedAt: Date?
        if let iatValue = payload["iat"] {
            guard let iat = number(iatValue), Date(timeIntervalSince1970: iat) <= now.addingTimeInterval(maxIssuedAtSkew) else {
                throw fail("The credential claims to be issued in the future.")
            }
            issuedAt = Date(timeIntervalSince1970: iat)
        }
        if let nbfValue = payload["nbf"] {
            guard let nbf = number(nbfValue), Date(timeIntervalSince1970: nbf) <= now.addingTimeInterval(maxIssuedAtSkew) else {
                throw fail("The credential is not valid yet.")
            }
        }
        if let alg = payload["_sd_alg"] as? String, alg != "sha-256" { throw fail("Unsupported disclosure digest algorithm.") }
        if payload["_sd_alg"] != nil, !(payload["_sd_alg"] is String) { throw fail("Unsupported disclosure digest algorithm.") }

        let resolved = try resolveDisclosures(parsed.disclosures, payload: payload)
        // Names and values are shown on screen. A name must already be clean display text, so no name
        // can turn into another (a hidden one included) by cleaning; values lose control and format
        // characters (bidi overrides included) and are bounded, like issuer metadata text.
        var claims: [String: String] = [:]
        for (name, value) in resolved where !hiddenClaims.contains(name) {
            guard IssuerMetadata.sanitize(name) == name else { throw fail("A claim has no displayable name.") }
            guard claims[name] == nil else { throw fail("A disclosure repeats a claim.") }
            guard claims.count < maxDisplayedClaims else { throw fail("The credential has too many claims.") }
            claims[name] = displayText(value)
        }
        return VerifiedCredential(issuedAt: issuedAt, expiresAt: Date(timeIntervalSince1970: exp), claims: claims)
    }

    // MARK: Disclosures

    private enum Disclosure {
        case objectMember(name: String, value: Any)
        case arrayElement(value: Any)
    }

    /// Resolve only disclosure digests reachable from the signed payload. An object member may
    /// contain another `_sd` list, and an array placeholder may disclose an object with its own
    /// digests (RFC 9901 section 6). The disclosure order does not have to be parent-first.
    private static func resolveDisclosures(_ disclosures: [String], payload: [String: Any]) throws -> [String: Any] {
        guard disclosures.count <= maxDisclosures else { throw fail("The credential has too many disclosures.") }
        var byDigest: [String: Disclosure] = [:]
        for disclosure in disclosures {
            let digest = Base64URL.encode(Data(SHA256.hash(data: Data(disclosure.utf8))))
            guard let data = Base64URL.decode(disclosure),
                  let array = (try? JSONSerialization.jsonObject(with: data)) as? [Any],
                  (array.count == 2 || array.count == 3), array[0] is String,
                  byDigest[digest] == nil
            else { throw fail("A disclosure is malformed.") }
            if array.count == 3 {
                guard let name = array[1] as? String, !name.isEmpty,
                      IssuerMetadata.sanitize(name) == name else {
                    throw fail("A disclosure is malformed.")
                }
                byDigest[digest] = .objectMember(name: name, value: array[2])
            } else {
                byDigest[digest] = .arrayElement(value: array[1])
            }
        }

        var referenced = Set<String>()
        var used = Set<String>()
        func take(_ digest: String) throws -> Disclosure? {
            // A digest may occur only once, including references to undisclosed values.
            guard referenced.insert(digest).inserted else {
                throw fail("The credential repeats a disclosure digest.")
            }
            if let disclosure = byDigest[digest] { used.insert(digest); return disclosure }
            return nil
        }

        func resolve(_ value: Any, depth: Int) throws -> Any {
            guard depth <= 64 else { throw fail("The credential has too many nested claims.") }
            if let object = value as? [String: Any] {
                var result: [String: Any] = [:]
                for (name, child) in object where name != "_sd" {
                    result[name] = try resolve(child, depth: depth + 1)
                }
                if let raw = object["_sd"] {
                    guard let digests = raw as? [String] else {
                        throw fail("The credential lists its disclosures incorrectly.")
                    }
                    for digest in digests {
                        guard let disclosure = try take(digest) else { continue }
                        guard case .objectMember(let name, let child) = disclosure,
                              result[name] == nil,
                              name != "_sd", name != "_sd_alg", name != "...",
                              (depth > 0 || !neverDisclosed.contains(name)) else {
                            throw fail("A disclosure repeats a claim.")
                        }
                        result[name] = try resolve(child, depth: depth + 1)
                    }
                }
                return result
            }
            if let array = value as? [Any] {
                var result: [Any] = []
                for element in array {
                    if let placeholder = element as? [String: Any], placeholder.count == 1,
                       let raw = placeholder["..."] {
                        guard let digest = raw as? String else {
                            throw fail("A disclosure placeholder is malformed.")
                        }
                        guard let disclosure = try take(digest) else { continue }
                        guard case .arrayElement(let child) = disclosure else {
                            throw fail("A disclosure has the wrong shape.")
                        }
                        result.append(try resolve(child, depth: depth + 1))
                    } else {
                        result.append(try resolve(element, depth: depth + 1))
                    }
                }
                return result
            }
            return value
        }

        guard let resolved = try resolve(payload, depth: 0) as? [String: Any],
              used.count == byDigest.count else {
            throw fail("A disclosure does not match the signed credential.")
        }
        return resolved
    }

    // MARK: Helpers

    private static func fail(_ message: String) -> WalletError { .invalidCredential(message) }

    private static func number(_ value: Any?) -> TimeInterval? {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { return nil }
        return number.doubleValue
    }

    /// `display` without control or format characters, bounded for the screen.
    static func displayText(_ value: Any) -> String {
        let text = String(display(value).unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) })
        return String(text.prefix(maxClaimValueLength))
    }

    /// A claim value as text for the card: strings as they are, other JSON as compact JSON.
    static func display(_ value: Any) -> String {
        if let text = value as? String { return text }
        if let number = value as? NSNumber {
            if CFGetTypeID(number) == CFBooleanGetTypeID() { return number.boolValue ? "true" : "false" }
            return number.stringValue
        }
        if value is NSNull { return "" }
        if JSONSerialization.isValidJSONObject(value),
           let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]),
           let text = String(data: data, encoding: .utf8) { return text }
        return String(describing: value)
    }
}

extension PublicJWK {
    nonisolated init?(from object: [String: Any]) {
        guard let kty = object["kty"] as? String, let crv = object["crv"] as? String,
              let x = object["x"] as? String, let y = object["y"] as? String else { return nil }
        guard let xData = Base64URL.decode(x), let yData = Base64URL.decode(y) else { return nil }
        self.init(x: xData, y: yData)
        self.kty = kty
        self.crv = crv
        self.kid = object["kid"] as? String
        self.use = object["use"] as? String
        self.alg = object["alg"] as? String
    }
}

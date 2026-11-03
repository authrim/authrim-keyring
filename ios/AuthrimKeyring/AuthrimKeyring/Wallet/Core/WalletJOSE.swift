import CryptoKit
import Foundation

/// Unpadded base64url (RFC 4648 section 5), as used by JOSE.
nonisolated enum Base64URL {
    static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Strict: only the base64url alphabet, no padding.
    static func decode(_ text: String) -> Data? {
        guard text.utf8.allSatisfy({ isAlphabet($0) }) else { return nil }
        var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        switch base64.count % 4 {
        case 0: break
        case 2: base64 += "=="
        case 3: base64 += "="
        default: return nil
        }
        return Data(base64Encoded: base64)
    }

    private static func isAlphabet(_ byte: UInt8) -> Bool {
        switch byte {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"),
             UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "-"), UInt8(ascii: "_"):
            true
        default:
            false
        }
    }
}

/// A public P-256 key in JWK form (the only key type the wallet creates or accepts).
nonisolated struct PublicJWK: Codable, Equatable, Sendable {
    var kty: String
    var crv: String
    var x: String
    var y: String
    var kid: String?
    var use: String?
    var alg: String?

    init(x: Data, y: Data) {
        kty = "EC"
        crv = "P-256"
        self.x = Base64URL.encode(x)
        self.y = Base64URL.encode(y)
    }

    /// From an uncompressed ANSI X9.63 point `04 || x || y`.
    init?(x963: Data) {
        guard x963.count == 65, x963.first == 0x04 else { return nil }
        self.init(x: x963.subdata(in: 1..<33), y: x963.subdata(in: 33..<65))
    }

    /// The members the wallet puts in a proof header: no `kid`, `use` or `alg`.
    var proofMembers: [String: String] { ["kty": kty, "crv": crv, "x": x, "y": y] }

    /// The same key (type, curve, coordinates), ignoring `kid`, `use` and `alg`.
    func isSameKey(as other: PublicJWK) -> Bool {
        kty == other.kty && crv == other.crv && x == other.x && y == other.y
    }

    /// The key as CryptoKit reads it, or nil when it is not a valid P-256 point.
    var cryptoKey: P256.Signing.PublicKey? {
        guard kty == "EC", crv == "P-256",
              let xData = Base64URL.decode(x), let yData = Base64URL.decode(y),
              xData.count == 32, yData.count == 32 else { return nil }
        return try? P256.Signing.PublicKey(rawRepresentation: xData + yData)
    }

    var thumbprint: Data { JWKThumbprint.compute(proofMembers) }
    var confirmationCode: String { JWKThumbprint.confirmationCode(thumbprint: thumbprint) }
}

/// RFC 7638 JWK thumbprints and the short confirmation code derived from them.
nonisolated enum JWKThumbprint {
    /// SHA-256 over the canonical JSON of the required members (lexicographic order, no whitespace).
    static func compute(_ jwk: [String: String]) -> Data {
        let required: [String]
        switch jwk["kty"] {
        case "RSA": required = ["e", "kty", "n"]
        case "OKP": required = ["crv", "kty", "x"]
        default: required = ["crv", "kty", "x", "y"]
        }
        let members = required.map { "\"\($0)\":\"\(jwk[$0] ?? "")\"" }
        return Data(SHA256.hash(data: Data(("{" + members.joined(separator: ",") + "}").utf8)))
    }

    /// First 8 characters of the unpadded RFC 4648 base32 of the thumbprint bytes, as `ABCD-EFGH`.
    /// The Authrim admin console shows the same code after issuance.
    static func confirmationCode(thumbprint: Data) -> String {
        let characters = Array(Base32.encode(thumbprint).prefix(8))
        return String(characters[0..<4]) + "-" + String(characters[4..<8])
    }
}

/// ES256 (ECDSA P-256 / SHA-256) in JOSE form: signatures are raw `r || s`, 64 bytes, not DER.
nonisolated enum JWS {
    struct Parts {
        let header: [String: Any]
        let payload: [String: Any]
        let signingInput: Data
        let signature: Data
    }

    static func parse(_ jwt: String) -> Parts? {
        let segments = jwt.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3,
              let headerData = Base64URL.decode(String(segments[0])),
              let payloadData = Base64URL.decode(String(segments[1])),
              let signature = Base64URL.decode(String(segments[2])),
              let header = (try? JSONSerialization.jsonObject(with: headerData)) as? [String: Any],
              let payload = (try? JSONSerialization.jsonObject(with: payloadData)) as? [String: Any]
        else { return nil }
        return Parts(
            header: header, payload: payload,
            signingInput: Data("\(segments[0]).\(segments[1])".utf8), signature: signature)
    }

    static func verifyES256(_ parts: Parts, with key: P256.Signing.PublicKey) -> Bool {
        guard parts.signature.count == 64,
              let signature = try? P256.Signing.ECDSASignature(rawRepresentation: parts.signature)
        else { return false }
        return key.isValidSignature(signature, for: parts.signingInput)
    }

    static func encodeSegment(_ object: [String: Any]) throws -> String {
        Base64URL.encode(try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]))
    }

    /// Builds `header.payload.signature`, signing `header.payload` with `sign`.
    static func make(
        header: [String: Any], payload: [String: Any], sign: (Data) throws -> Data
    ) throws -> String {
        let signingInput = try encodeSegment(header) + "." + encodeSegment(payload)
        let signature = try sign(Data(signingInput.utf8))
        return signingInput + "." + Base64URL.encode(signature)
    }
}

/// The proof of possession sent with a credential request (OpenID4VCI 1.0 Appendix F.1).
nonisolated enum ProofJWT {
    static let type = "openid4vci-proof+jwt"

    /// Anonymous (pre-authorized) proof: no `iss`. `nonce` is omitted when the issuer has no nonce endpoint.
    static func make(
        audience: String, nonce: String?, issuedAt: Date, key: PublicJWK, sign: (Data) throws -> Data
    ) throws -> String {
        var payload: [String: Any] = ["aud": audience, "iat": Int(issuedAt.timeIntervalSince1970)]
        if let nonce { payload["nonce"] = nonce }
        let header: [String: Any] = ["alg": "ES256", "typ": type, "jwk": key.proofMembers]
        return try JWS.make(header: header, payload: payload, sign: sign)
    }
}

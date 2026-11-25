import CryptoKit
import Foundation

/// JWE compact serialization with `ECDH-ES` (direct key agreement) on P-256 and `A128GCM` or
/// `A256GCM` content encryption (RFC 7516, RFC 7518 sections 4.6 and 5.3): the response encryption
/// of OpenID4VP `direct_post.jwt` as HAIP 1.0 requires.
nonisolated enum WalletJWE {
    static let supportedContentEncryption = ["A256GCM", "A128GCM"]

    static func keyBits(for enc: String) -> Int? {
        switch enc {
        case "A128GCM": 128
        case "A256GCM": 256
        default: nil
        }
    }

    /// Encrypts to the recipient's P-256 public key with a fresh ephemeral key.
    static func encrypt(_ plaintext: Data, to recipient: PublicJWK, kid: String?, enc: String) throws -> String {
        guard let bits = keyBits(for: enc), recipient.kty == "EC", recipient.crv == "P-256",
              let x = Base64URL.decode(recipient.x), let y = Base64URL.decode(recipient.y),
              x.count == 32, y.count == 32,
              let recipientKey = try? P256.KeyAgreement.PublicKey(x963Representation: Data([4]) + x + y)
        else { throw WalletError.invalidRequest("The response encryption key is not usable.") }
        let ephemeral = P256.KeyAgreement.PrivateKey()
        guard let epk = PublicJWK(x963: ephemeral.publicKey.x963Representation) else {
            throw WalletError.keyUnavailable("The ephemeral key could not be read.")
        }
        let secret = try ephemeral.sharedSecretFromKeyAgreement(with: recipientKey)
        let z = secret.withUnsafeBytes { Data($0) }
        let key = SymmetricKey(data: concatKDF(z: z, algorithmID: enc, apu: Data(), apv: Data(), bits: bits))
        var header: [String: Any] = ["alg": "ECDH-ES", "enc": enc, "epk": epk.proofMembers]
        if let kid { header["kid"] = kid }
        let encodedHeader = try JWS.encodeSegment(header)
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(
            plaintext, using: key, nonce: nonce, authenticating: Data(encodedHeader.utf8))
        return [encodedHeader, "", Base64URL.encode(Data(nonce)),
                Base64URL.encode(sealed.ciphertext), Base64URL.encode(sealed.tag)].joined(separator: ".")
    }

    /// The Concat KDF of RFC 7518 section 4.6.2 with SHA-256 (one round covers 128 and 256 bits).
    static func concatKDF(z: Data, algorithmID: String, apu: Data, apv: Data, bits: Int) -> Data {
        func field(_ data: Data) -> Data { u32(data.count) + data }
        let otherInfo = field(Data(algorithmID.utf8)) + field(apu) + field(apv) + u32(bits)
        let digest = SHA256.hash(data: u32(1) + z + otherInfo)
        return Data(digest).prefix(bits / 8)
    }

    private static func u32(_ value: Int) -> Data {
        withUnsafeBytes(of: UInt32(value).bigEndian) { Data($0) }
    }
}

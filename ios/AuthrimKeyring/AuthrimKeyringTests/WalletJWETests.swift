import CryptoKit
import Foundation
import Testing
@testable import AuthrimKeyring

@Suite
struct WalletJWETests {
    /// RFC 7518 Appendix C: ECDH-ES Concat KDF with A128GCM, apu "Alice", apv "Bob".
    @Test func concatKDFMatchesRFC7518AppendixC() {
        let z = Data([158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156,
                      251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196])
        let key = WalletJWE.concatKDF(
            z: z, algorithmID: "A128GCM", apu: Data("Alice".utf8), apv: Data("Bob".utf8), bits: 128)
        #expect(Base64URL.encode(key) == "VqqN6vgjbSBcIijNcacQGg")
    }

    /// Decrypts with the recipient's private key, the way a verifier does.
    static func decrypt(_ jwe: String, with key: P256.KeyAgreement.PrivateKey) throws -> (header: [String: Any], plaintext: Data) {
        let segments = jwe.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        try #require(segments.count == 5)
        #expect(segments[1].isEmpty)
        let headerData = try #require(Base64URL.decode(segments[0]))
        let header = try #require(JSONSerialization.jsonObject(with: headerData) as? [String: Any])
        let epkMembers = try #require(header["epk"] as? [String: Any])
        let epk = try #require(PublicJWK(from: epkMembers))
        let x = try #require(Base64URL.decode(epk.x)), y = try #require(Base64URL.decode(epk.y))
        let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: Data([4]) + x + y)
        let z = try key.sharedSecretFromKeyAgreement(with: ephemeral).withUnsafeBytes { Data($0) }
        let enc = try #require(header["enc"] as? String)
        let bits = try #require(WalletJWE.keyBits(for: enc))
        let derived = SymmetricKey(data: WalletJWE.concatKDF(z: z, algorithmID: enc, apu: Data(), apv: Data(), bits: bits))
        let iv = try #require(Base64URL.decode(segments[2]))
        let ciphertext = try #require(Base64URL.decode(segments[3]))
        let tag = try #require(Base64URL.decode(segments[4]))
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: iv), ciphertext: ciphertext, tag: tag)
        return (header, try AES.GCM.open(box, using: derived, authenticating: Data(segments[0].utf8)))
    }

    @Test(arguments: ["A128GCM", "A256GCM"]) func roundTripsWithTheRecipientKey(enc: String) throws {
        let recipient = P256.KeyAgreement.PrivateKey()
        let jwk = try #require(PublicJWK(x963: recipient.publicKey.x963Representation))
        let jwe = try WalletJWE.encrypt(Data("hello".utf8), to: jwk, kid: "req-1", enc: enc)
        let opened = try Self.decrypt(jwe, with: recipient)
        #expect(opened.plaintext == Data("hello".utf8))
        #expect(opened.header["alg"] as? String == "ECDH-ES")
        #expect(opened.header["enc"] as? String == enc)
        #expect(opened.header["kid"] as? String == "req-1")
        #expect(opened.header["apu"] == nil && opened.header["apv"] == nil)
    }

    @Test func eachMessageUsesAFreshEphemeralKeyAndNonce() throws {
        let recipient = P256.KeyAgreement.PrivateKey()
        let jwk = try #require(PublicJWK(x963: recipient.publicKey.x963Representation))
        let first = try WalletJWE.encrypt(Data("a".utf8), to: jwk, kid: nil, enc: "A256GCM")
        let second = try WalletJWE.encrypt(Data("a".utf8), to: jwk, kid: nil, enc: "A256GCM")
        #expect(first != second)
        #expect(try Self.decrypt(first, with: recipient).header["kid"] == nil)
    }

    @Test func tamperedHeaderOrAlgorithmIsRefused() throws {
        let recipient = P256.KeyAgreement.PrivateKey()
        let jwk = try #require(PublicJWK(x963: recipient.publicKey.x963Representation))
        #expect(throws: WalletError.self) { try WalletJWE.encrypt(Data(), to: jwk, kid: nil, enc: "A192GCM") }
        let jwe = try WalletJWE.encrypt(Data("x".utf8), to: jwk, kid: "k", enc: "A128GCM")
        var segments = jwe.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        let header = try #require(Base64URL.decode(segments[0]))
        var object = try #require(JSONSerialization.jsonObject(with: header) as? [String: Any])
        object["kid"] = "other"
        segments[0] = try JWS.encodeSegment(object)
        #expect(throws: (any Error).self) { try Self.decrypt(segments.joined(separator: "."), with: recipient) }
    }

    @Test func authorityKeyIdentifierIsReadFromCertificates() throws {
        let ca = try #require(Data(base64Encoded: AuthrimPKIFixture.issuingCA))
        let root = try #require(Data(base64Encoded: AuthrimPKIFixture.root))
        let leaf = try #require(Data(base64Encoded: AuthrimPKIFixture.leaf))
        // The leaf names the issuing CA, the issuing CA names the root, the self-signed root has none.
        let leafAKI = try #require(CertificateKeyIdentifiers.authorityKeyIdentifier(of: leaf))
        let caAKI = try #require(CertificateKeyIdentifiers.authorityKeyIdentifier(of: ca))
        #expect(leafAKI.count == 20 && caAKI.count == 20 && leafAKI != caAKI)
        // The self-signed root names itself; a certificate without the extension yields nil.
        #expect(CertificateKeyIdentifiers.authorityKeyIdentifier(of: root) != leafAKI)
        #expect(!CertificateKeyIdentifiers.hasExtension(oid: [0x55, 0x1D, 0x25], in: leaf))
        #expect(CertificateKeyIdentifiers.hasExtension(oid: [0x55, 0x1D, 0x23], in: leaf))
        #expect(CertificateKeyIdentifiers.hasExtension(oid: [0x55, 0x1D, 0x25], in: Data([1, 2, 3])))
    }
}

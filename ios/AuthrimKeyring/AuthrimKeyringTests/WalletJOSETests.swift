import CryptoKit
import Foundation
import Testing
@testable import AuthrimKeyring

struct WalletJOSETests {
    @Test func base64URLRoundTripAndStrictness() {
        let data = Data([0xfb, 0xff, 0xfe, 0x01])
        #expect(Base64URL.encode(data) == "-__-AQ")
        #expect(Base64URL.decode("-__-AQ") == data)
        #expect(Base64URL.decode("-__-AQ==") == nil)
        #expect(Base64URL.decode("a+b/") == nil)
        #expect(Base64URL.decode("A") == nil)
    }

    @Test func rfc7638ExampleThumbprintAndConfirmationCode() {
        // RFC 7638 section 3.1 example RSA key.
        let jwk = [
            "kty": "RSA", "e": "AQAB",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "alg": "RS256", "kid": "2011-04-29",
        ]
        let thumbprint = JWKThumbprint.compute(jwk)
        #expect(Base64URL.encode(thumbprint) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
        let base32 = Base32.encode(thumbprint)
        #expect(base32.count == 52)
        let code = JWKThumbprint.confirmationCode(thumbprint: thumbprint)
        #expect(code == String(base32.prefix(4)) + "-" + String(base32.dropFirst(4).prefix(4)))
        #expect(code == "G43M-XMLY") // bytes 37 36 cb b1 78 ... -> 5-bit groups G 4 3 M X M L Y
    }

    @Test func ecThumbprintUsesCanonicalMembers() {
        let jwk = PublicJWK(x: Data(repeating: 1, count: 32), y: Data(repeating: 2, count: 32))
        let canonical = #"{"crv":"P-256","kty":"EC","x":"\#(jwk.x)","y":"\#(jwk.y)"}"#
        #expect(jwk.thumbprint == Data(SHA256.hash(data: Data(canonical.utf8))))
    }

    @Test func proofJWTStructureAndSignature() throws {
        let signer = TestSigner(tag: "t", key: P256.Signing.PrivateKey())
        let issuedAt = Date(timeIntervalSince1970: 1_800_000_000)
        let jwt = try ProofJWT.make(
            audience: "https://issuer.example.com", nonce: "n-123", issuedAt: issuedAt,
            key: signer.publicJWK, sign: signer.sign)
        let parts = try #require(JWS.parse(jwt))
        #expect(parts.header["alg"] as? String == "ES256")
        #expect(parts.header["typ"] as? String == "openid4vci-proof+jwt")
        let jwk = try #require(parts.header["jwk"] as? [String: String])
        #expect(Set(jwk.keys) == ["kty", "crv", "x", "y"])
        #expect(jwk["x"] == signer.publicJWK.x)
        #expect(parts.payload["aud"] as? String == "https://issuer.example.com")
        #expect(parts.payload["nonce"] as? String == "n-123")
        #expect(parts.payload["iat"] as? Int == 1_800_000_000)
        #expect(parts.payload["iss"] == nil)
        #expect(parts.signature.count == 64)
        #expect(JWS.verifyES256(parts, with: signer.key.publicKey))
        #expect(!JWS.verifyES256(parts, with: P256.Signing.PrivateKey().publicKey))
    }

    @Test func derSignatureConvertsToRaw() throws {
        let key = P256.Signing.PrivateKey()
        let signature = try key.signature(for: Data("hello".utf8))
        let raw = try #require(DERSignature.rawES256(signature.derRepresentation))
        #expect(raw == signature.rawRepresentation)
        #expect(DERSignature.rawES256(Data([1, 2, 3])) == nil)
    }

    @Test func localizedNamePrefersDeviceThenEnglish() {
        let entries: [[String: Any]] = [["name": "English", "locale": "en"], ["name": "日本語", "locale": "ja"], ["name": "Deutsch", "locale": "de-DE"]]
        #expect(IssuerMetadata.localizedName(entries, languages: ["ja-JP", "en-US"]) == "日本語")
        #expect(IssuerMetadata.localizedName(entries, languages: ["de"]) == "Deutsch")
        #expect(IssuerMetadata.localizedName(entries, languages: ["fr-FR"]) == "English")
        #expect(IssuerMetadata.localizedName([["name": "Only", "locale": "fr"]], languages: ["ja"]) == "Only")
        #expect(IssuerMetadata.localizedName(nil, languages: ["en"]) == nil)
    }
}

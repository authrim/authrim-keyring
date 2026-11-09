import CryptoKit
import Foundation
import Testing
@testable import AuthrimKeyring

struct WalletSDJWTTests {
    let issuer = TestIssuer()
    let holder = TestSigner(tag: "h", key: P256.Signing.PrivateKey())

    private func verify(_ text: String, key: PublicJWK? = nil, vct: String = TestIssuer.vct, holderKey: PublicJWK? = nil) throws -> VerifiedCredential {
        let parsed = try ParsedSDJWT(text)
        let issuerKey = try key ?? #require(PublicJWK(from: issuer.issuerJWK))
        return try SDJWTVerifier.verify(
            parsed, issuerKey: issuerKey, expectedIssuer: TestIssuer.base, expectedVct: vct,
            holderKey: holderKey ?? holder.publicJWK, now: Date())
    }

    private func rejects(_ text: String, vct: String = TestIssuer.vct, key: PublicJWK? = nil) {
        #expect(throws: WalletError.self) { try verify(text, key: key, vct: vct) }
    }

    private func disclosure(_ elements: [Any]) throws -> (encoded: String, digest: String) {
        let encoded = Base64URL.encode(try JSONSerialization.data(withJSONObject: elements))
        let digest = Base64URL.encode(Data(SHA256.hash(data: Data(encoded.utf8))))
        return (encoded, digest)
    }

    @Test func happyPath() throws {
        let result = try verify(try issuer.sdJwt(holder: holder.publicJWK))
        #expect(result.claims == ["email": "admin@example.com", "sub": "user-1"])
        #expect(result.expiresAt > Date())
        #expect(try SDJWTVerifier.keyID(of: ParsedSDJWT(issuer.sdJwt(holder: holder.publicJWK))) == "key-1")
    }

    @Test func claimTextIsSanitizedForDisplay() throws {
        var options = TestIssuer.Options()
        options.extraPayload = ["role": "admin\u{202E}nimda\u{0007}", "note": String(repeating: "x", count: 5_000)]
        let result = try verify(try issuer.sdJwt(holder: holder.publicJWK, options))
        #expect(result.claims["role"] == "adminnimda")
        #expect(result.claims["note"]?.count == SDJWTVerifier.maxClaimValueLength)
    }

    @Test func claimNamesThatCollideAfterSanitizingAreRejected() throws {
        var options = TestIssuer.Options()
        options.extraPayload = ["sub\u{200B}": "other"]
        rejects(try issuer.sdJwt(holder: holder.publicJWK, options))
    }

    @Test func claimNamesThatCleanIntoHiddenNamesAreRejected() throws {
        var options = TestIssuer.Options()
        options.extraPayload = ["cnf\u{200B}": "spoofed"]
        rejects(try issuer.sdJwt(holder: holder.publicJWK, options))
    }

    @Test func tooManyClaimsAreRejected() throws {
        var options = TestIssuer.Options()
        options.extraPayload = Dictionary(uniqueKeysWithValues: (0..<SDJWTVerifier.maxDisplayedClaims).map { ("c\($0)", "v") })
        rejects(try issuer.sdJwt(holder: holder.publicJWK, options))
    }

    @Test func badSignature() throws {
        var options = TestIssuer.Options()
        options.signWith = P256.Signing.PrivateKey()
        rejects(try issuer.sdJwt(holder: holder.publicJWK, options))
    }

    @Test func wrongIssuer() throws {
        var options = TestIssuer.Options()
        options.iss = "https://evil.example.com"
        rejects(try issuer.sdJwt(holder: holder.publicJWK, options))
    }

    @Test func wrongVct() throws {
        rejects(try issuer.sdJwt(holder: holder.publicJWK), vct: "https://issuer.example.com/vct/other")
    }

    @Test func wrongType() throws {
        var options = TestIssuer.Options()
        options.typ = "JWT"
        rejects(try issuer.sdJwt(holder: holder.publicJWK, options))
    }

    @Test func confirmationKeyMismatch() throws {
        var options = TestIssuer.Options()
        options.cnf = TestSigner(tag: "o", key: P256.Signing.PrivateKey()).publicJWK
        rejects(try issuer.sdJwt(holder: holder.publicJWK, options))
    }

    @Test func rejectsCriticalHeader() throws {
        var options = TestIssuer.Options()
        options.extraHeader = ["crit": ["exp"]]
        rejects(try issuer.sdJwt(holder: holder.publicJWK, options))
    }

    @Test func notBeforeInFutureIsRejected() throws {
        var options = TestIssuer.Options()
        options.extraPayload = ["nbf": Int(Date().addingTimeInterval(3600).timeIntervalSince1970)]
        rejects(try issuer.sdJwt(holder: holder.publicJWK, options))
    }

    @Test func notBeforeWithinSkewOrPastIsAccepted() throws {
        var options = TestIssuer.Options()
        options.extraPayload = ["nbf": Int(Date().addingTimeInterval(60).timeIntervalSince1970)]
        _ = try verify(try issuer.sdJwt(holder: holder.publicJWK, options))
        options.extraPayload = ["nbf": Int(Date().addingTimeInterval(-60).timeIntervalSince1970)]
        _ = try verify(try issuer.sdJwt(holder: holder.publicJWK, options))
    }

    @Test(arguments: [true, "soon"] as [Any])
    func nonNumericNotBeforeIsRejected(value: Any) throws {
        var options = TestIssuer.Options()
        options.extraPayload = ["nbf": value]
        rejects(try issuer.sdJwt(holder: holder.publicJWK, options))
    }

    @Test(arguments: ["iss", "nbf", "exp", "iat", "cnf", "vct", "status", "_sd", "_sd_alg", "..."])
    func rejectsDisclosureOfProtectedClaim(name: String) throws {
        var options = TestIssuer.Options()
        options.disclosureName = name
        rejects(try issuer.sdJwt(holder: holder.publicJWK, options))
    }

    @Test func rejectsDuplicateDigests() throws {
        var options = TestIssuer.Options()
        options.duplicateDigest = true
        rejects(try issuer.sdJwt(holder: holder.publicJWK, options))
    }

    @Test func rejectsDigestRepeatedAsArrayElement() throws {
        var options = TestIssuer.Options()
        options.duplicateDigestInArray = true
        rejects(try issuer.sdJwt(holder: holder.publicJWK, options))
    }

    @Test func acceptsNestedObjectDisclosuresInAnyOrder() throws {
        let inner = try disclosure(["salt-inner", "city", "Paris"])
        let parent = try disclosure([
            "salt-parent", "address", ["country": "FR", "_sd": [inner.digest]] as [String: Any],
        ])
        let base = try ParsedSDJWT(issuer.sdJwt(holder: holder.publicJWK))
        let parts = try #require(JWS.parse(base.issuerJWT))
        var payload = parts.payload
        var digests = try #require(payload["_sd"] as? [String])
        digests.append(parent.digest)
        payload["_sd"] = digests
        let jwt = try JWS.make(header: parts.header, payload: payload) {
            try issuer.issuerKey.signature(for: $0).rawRepresentation
        }
        // Inner disclosure deliberately appears before the parent in the serialized SD-JWT.
        let text = ([jwt] + base.disclosures + [inner.encoded, parent.encoded]).joined(separator: "~") + "~"
        let result = try verify(text)
        #expect(result.claims["address"] == #"{"city":"Paris","country":"FR"}"#)
    }

    @Test func acceptsDisclosedArrayElement() throws {
        let element = try disclosure(["salt-item", ["city": "Paris"]])
        var options = TestIssuer.Options()
        options.extraPayload = ["addresses": [["...": element.digest]]]
        let text = try issuer.sdJwt(holder: holder.publicJWK, options) + element.encoded + "~"
        let result = try verify(text)
        #expect(result.claims["addresses"] == #"[{"city":"Paris"}]"#)
    }

    @Test func rejectsDetachedNestedDisclosure() throws {
        let detached = try disclosure(["salt-inner", "city", "Paris"])
        let text = try issuer.sdJwt(holder: holder.publicJWK) + detached.encoded + "~"
        rejects(text)
    }

    @Test func expired() throws {
        var options = TestIssuer.Options()
        options.exp = Date().addingTimeInterval(-10)
        rejects(try issuer.sdJwt(holder: holder.publicJWK, options))
    }

    @Test func issuedInTheFuture() throws {
        var options = TestIssuer.Options()
        options.iat = Date().addingTimeInterval(3600)
        rejects(try issuer.sdJwt(holder: holder.publicJWK, options))
    }

    @Test func tamperedDisclosure() throws {
        var options = TestIssuer.Options()
        options.tamperDisclosure = true
        rejects(try issuer.sdJwt(holder: holder.publicJWK, options))
    }

    @Test func wrongIssuerKey() throws {
        let other = TestSigner(tag: "o", key: P256.Signing.PrivateKey()).publicJWK
        rejects(try issuer.sdJwt(holder: holder.publicJWK), key: other)
    }

    @Test func malformedShapes() throws {
        let good = try issuer.sdJwt(holder: holder.publicJWK)
        #expect(throws: WalletError.self) { try ParsedSDJWT(String(good.dropLast())) }  // trailing key binding slot missing
        #expect(throws: WalletError.self) { try ParsedSDJWT("only-a-jwt") }
        #expect(throws: WalletError.self) { try ParsedSDJWT(good + "~") }  // empty disclosure
    }
}

import Foundation
import Testing
@testable import AuthrimKeyring

@Suite
struct WalletDPoPTests {
    @Test func tokenProofUsesFreshSignedJTIAndPublicKey() throws {
        let key = try WalletDPoPKey()
        let url = try #require(URL(string: "https://authorization.example.com/token"))
        let first = try #require(JWS.parse(key.proof(
            method: "post", url: url, issuedAt: Date(timeIntervalSince1970: 1_700_000_000))))
        let second = try #require(JWS.parse(key.proof(
            method: "POST", url: url, issuedAt: Date(timeIntervalSince1970: 1_700_000_000))))

        #expect(first.header["typ"] as? String == "dpop+jwt")
        #expect(first.header["alg"] as? String == "ES256")
        #expect(first.header["jwk"] as? [String: String] == key.publicJWK.proofMembers)
        #expect(first.payload["htm"] as? String == "POST")
        #expect(first.payload["htu"] as? String == url.absoluteString)
        #expect(first.payload["iat"] as? Int == 1_700_000_000)
        #expect(first.payload["ath"] == nil)
        let firstJTI = try #require(first.payload["jti"] as? String)
        let secondJTI = try #require(second.payload["jti"] as? String)
        #expect(!firstJTI.isEmpty && firstJTI != secondJTI)
        let publicKey = try #require(key.publicJWK.cryptoKey)
        #expect(JWS.verifyES256(first, with: publicKey))
        #expect(JWS.verifyES256(second, with: publicKey))
    }

    @Test func resourceProofHashesTokenAndOmitsURLQueryAndFragment() throws {
        let key = try WalletDPoPKey()
        let url = try #require(URL(string: "https://backend.example.com/credential?dataset=1#ignored"))
        let jwt = try key.proof(
            method: "POST", url: url, accessToken: "test-token", nonce: "server-nonce",
            issuedAt: Date(timeIntervalSince1970: 1_700_000_001))
        let parts = try #require(JWS.parse(jwt))

        #expect(parts.payload["htu"] as? String == "https://backend.example.com/credential")
        #expect(parts.payload["htm"] as? String == "POST")
        #expect(parts.payload["ath"] as? String == "TF3Jt3CJBfd_Xl0WMWtd-0JeaMsybc1VqGDpCncHAx4")
        #expect(parts.payload["nonce"] as? String == "server-nonce")
        #expect(parts.payload["iat"] as? Int == 1_700_000_001)
        let publicKey = try #require(key.publicJWK.cryptoKey)
        #expect(JWS.verifyES256(parts, with: publicKey))
    }

    @Test func rejectsUnsafeProofInputs() throws {
        let key = try WalletDPoPKey()
        let url = try #require(URL(string: "https://backend.example.com/credential"))
        #expect(throws: WalletError.self) { try key.proof(method: "POST\nGET", url: url) }
        #expect(throws: WalletError.self) { try key.proof(method: "POST", url: url, accessToken: "") }
        #expect(throws: WalletError.self) { try key.proof(method: "POST", url: url, accessToken: "é") }
        let localURL = try #require(URL(string: "https://localhost/credential"))
        #expect(throws: WalletError.self) { try key.proof(method: "POST", url: localURL) }
    }
}

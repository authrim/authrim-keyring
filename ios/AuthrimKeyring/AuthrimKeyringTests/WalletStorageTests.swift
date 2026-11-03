import CryptoKit
import Foundation
import Testing
@testable import AuthrimKeyring

/// Keychain-backed pieces. They run in the app-hosted test bundle on the simulator, where holder keys
/// use the DEBUG software fallback; the Secure Enclave path needs a real device.
@Suite(.serialized)
struct WalletStorageTests {
    private func credential(tag: String) -> StoredCredential {
        StoredCredential(
            id: UUID(), issuer: URL(string: "https://issuer.example.com")!, issuerDisplayName: nil,
            credentialConfigurationId: "admin", vct: "v", credentialName: "Admin", claims: ["email": "a@example.com"],
            issuedAt: Date(), expiresAt: Date().addingTimeInterval(60), keyTag: tag,
            confirmationCode: "ABCD-EFGH", sdJwt: "a.b.c~")
    }

    @Test func storeRoundTripDeletesItsKey() throws {
        let deletedTags = Box<[String]>([])
        let store = KeychainCredentialStore(service: "com.authrim.keyring.vc.test.\(UUID().uuidString)") { deletedTags.value.append($0) }
        let item = credential(tag: "tag-1")
        try store.save(item)
        try store.save(item)  // update in place
        #expect(try store.loadAll() == [item])
        try store.delete(item)
        #expect(try store.loadAll().isEmpty)
        #expect(deletedTags.value == ["tag-1"])
    }

    @Test func defaultServiceIsSeparateFromAccountStores() {
        #expect(KeychainCredentialStore.service == "com.authrim.keyring.vc")
        #expect(KeychainStore().service != KeychainCredentialStore.service)
    }

    #if targetEnvironment(simulator) && DEBUG
    @Test func simulatorHolderKeySignsAndDeletes() throws {
        let tag = HolderKey.makeTag()
        let key = try HolderKey.create(tag: tag)
        defer { try? HolderKey.delete(tag: tag) }
        let message = Data("message".utf8)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: key.sign(message))
        #expect(try #require(key.publicJWK.cryptoKey).isValidSignature(signature, for: message))
        #expect(key.publicJWK.x.count == 43 && key.publicJWK.y.count == 43)
        try HolderKey.delete(tag: tag)
        try HolderKey.delete(tag: tag)  // idempotent
    }
    #endif
}

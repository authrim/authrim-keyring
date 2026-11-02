import CryptoKit
import Foundation

/// The parts of WebAuthn an authenticator produces: authenticator data, the
/// attestation object for a new credential, and assertion signatures.
nonisolated enum WebAuthn {
    /// COSE identifier of ES256 (ECDSA with P-256 and SHA-256), the only algorithm offered.
    static let es256 = -7

    /// Identifies Authrim Keyring as the authenticator model to relying parties.
    static let aaguid = UUID(uuidString: "6F1C5E2A-7B4D-4E8F-9A3C-2D5B8E1F0A47")!

    struct Flags: OptionSet {
        let rawValue: UInt8
        static let userPresent = Flags(rawValue: 0x01)
        static let userVerified = Flags(rawValue: 0x04)
        static let backupEligible = Flags(rawValue: 0x08)
        static let backedUp = Flags(rawValue: 0x10)
        static let attestedCredentialData = Flags(rawValue: 0x40)
    }

    /// Flags for a passkey. iOS only accepts passkeys from other apps that are
    /// marked backup eligible and backed up (BE and BS), so every passkey is, even
    /// one Keyring keeps on this device only; that choice is Keyring's own storage.
    static func flags(isUserVerified: Bool, attested: Bool) -> Flags {
        var flags: Flags = [.userPresent, .backupEligible, .backedUp]
        if isUserVerified { flags.insert(.userVerified) }
        if attested { flags.insert(.attestedCredentialData) }
        return flags
    }

    /// `rpIdHash ‖ flags ‖ signCount`, followed by the attested credential data
    /// when a credential is created.
    static func authenticatorData(
        relyingParty: String,
        flags: Flags,
        credential: (id: Data, publicKey: P256.Signing.PublicKey)? = nil
    ) -> Data {
        var data = Data(SHA256.hash(data: Data(relyingParty.utf8)))
        data.append(flags.rawValue)
        // A counter of zero tells the relying party not to expect one, as for synced passkeys.
        data.append(contentsOf: [0, 0, 0, 0])
        if let credential {
            data.append(contentsOf: withUnsafeBytes(of: aaguid.uuid) { Array($0) })
            data.append(UInt8(credential.id.count >> 8))
            data.append(UInt8(credential.id.count & 0xFF))
            data.append(credential.id)
            data.append(coseKey(credential.publicKey))
        }
        return data
    }

    /// The public key as a COSE_Key map: kty EC2, alg ES256, crv P-256, x, y.
    static func coseKey(_ key: P256.Signing.PublicKey) -> Data {
        // x963 is 0x04 ‖ x ‖ y.
        let point = key.x963Representation
        let x = point.subdata(in: 1..<33)
        let y = point.subdata(in: 33..<65)
        var cbor = CBOR()
        cbor.map(count: 5)
        cbor.int(1); cbor.int(2)
        cbor.int(3); cbor.int(es256)
        cbor.int(-1); cbor.int(1)
        cbor.int(-2); cbor.bytes(x)
        cbor.int(-3); cbor.bytes(y)
        return cbor.data
    }

    /// `{"fmt": "none", "attStmt": {}, "authData": …}`, with keys in canonical order.
    static func attestationObject(authenticatorData: Data) -> Data {
        var cbor = CBOR()
        cbor.map(count: 3)
        cbor.text("fmt"); cbor.text("none")
        cbor.text("attStmt"); cbor.map(count: 0)
        cbor.text("authData"); cbor.bytes(authenticatorData)
        return cbor.data
    }

}

/// Just enough of CBOR (RFC 8949) for COSE keys and attestation objects.
nonisolated struct CBOR {
    private(set) var data = Data()

    mutating func int(_ value: Int) {
        if value >= 0 {
            head(major: 0, UInt64(value))
        } else {
            head(major: 1, UInt64(-1 - value))
        }
    }

    mutating func bytes(_ value: Data) {
        head(major: 2, UInt64(value.count))
        data.append(value)
    }

    mutating func text(_ value: String) {
        let utf8 = Data(value.utf8)
        head(major: 3, UInt64(utf8.count))
        data.append(utf8)
    }

    mutating func map(count: Int) {
        head(major: 5, UInt64(count))
    }

    private mutating func head(major: UInt8, _ value: UInt64) {
        let type = major << 5
        switch value {
        case 0..<24:
            data.append(type | UInt8(value))
        case 24...0xFF:
            data.append(type | 24)
            data.append(UInt8(value))
        case 0x100...0xFFFF:
            data.append(type | 25)
            data.append(contentsOf: [UInt8(value >> 8), UInt8(value & 0xFF)])
        case 0x10000...0xFFFF_FFFF:
            data.append(type | 26)
            data.append(contentsOf: (0..<4).reversed().map { UInt8((value >> (8 * UInt64($0))) & 0xFF) })
        default:
            data.append(type | 27)
            data.append(contentsOf: (0..<8).reversed().map { UInt8((value >> (8 * UInt64($0))) & 0xFF) })
        }
    }
}

import CryptoKit
import Foundation
import Security

/// A separate, opt-in interoperability policy for the EUDI reference issuer. It deliberately
/// does not claim that a LoTE was verified. Its CA certificates are pinned from the EUDI iOS
/// reference wallet at commit 00d8c020af926cc3d497a9704fa4ee0c189a9d9e, not from a QR,
/// credential x5c, issuer metadata or the downloaded LoTE. The issuer's FormEU configuration
/// lists the eleven SD-JWT VC configurations corresponding to the VCTs below and uses the LU document signer;
/// the EU configuration also issues PID with the EU signer.
nonisolated struct EUDITestStaticTrustPolicy: Sendable {
    private static let issuerIdentifier = "https://issuer.eudiw.dev"

    private static let categoriesByVCT: [String: EUDITestMode.Category] = [
        "urn:eudi:pid:1": .pid,
        "urn:eudi:ehic:1": .pubEAA,
        "urn:eu.europa.ec.eudi:hiid:1": .pubEAA,
        "urn:eu.europa.ec.eudi:diploma:1:1": .other,
        "urn:eu.europa.ec.eudi:iban:1": .other,
        "urn:eu.europa.ec.eudi:learning:credential:1": .other,
        "urn:eu.europa.ec.eudi:msisdn:1": .other,
        "urn:eu.europa.ec.eudi:pda1:1": .other,
        "urn:eu.europa.ec.eudi:por:1": .other,
        "urn:eu.europa.ec.eudi:tax:1:1": .other,
        "urn:eu.europa.ec.eudi:tax:1": .other,
    ]

    // Wallet/Certificate/pidissuerca02_lu.der and pidissuerca02_eu.der in the pinned
    // reference-wallet commit. Fingerprints are checked again at every use.
    private static let luRoot = "MIIC0zCCAnmgAwIBAgIUYGz2Xxw7UFgSmRsIkFTTBclg8fcwCgYIKoZIzj0EAwMwVzEZMBcGA1UEAwwQUElEIElzc3VlciBDQSAwMjEtMCsGA1UECgwkRVVESSBXYWxsZXQgUmVmZXJlbmNlIEltcGxlbWVudGF0aW9uMQswCQYDVQQGEwJMVTAeFw0yNTA0MDkwMDA1MzlaFw0zNDA3MDYwMDA1MzhaMFcxGTAXBgNVBAMMEFBJRCBJc3N1ZXIgQ0EgMDIxLTArBgNVBAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMCTFUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR6X1NlEGbdWUWiUrSA/YiNpcZeI95z2MglbvISRO19YUc4GvPTevbg/Fm9MekJeHqRQO4GHTlBPNGM2aiBtu5Mo4IBITCCAR0wEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBRcYvvRpiZ6Zz81VxQ4+AdY4Iez8DATBgNVHSUEDDAKBggrgQICAAABBzBDBgNVHR8EPDA6MDigNqA0hjJodHRwczovL3ByZXByb2QucGtpLmV1ZGl3LmRldi9jcmwvcGlkX0NBX0xVXzAyLmNybDAdBgNVHQ4EFgQUXGL70aYmemc/NVcUOPgHWOCHs/AwDgYDVR0PAQH/BAQDAgEGMF0GA1UdEgRWMFSGUmh0dHBzOi8vZ2l0aHViLmNvbS9ldS1kaWdpdGFsLWlkZW50aXR5LXdhbGxldC9hcmNoaXRlY3R1cmUtYW5kLXJlZmVyZW5jZS1mcmFtZXdvcmswCgYIKoZIzj0EAwMDSAAwRQIgd69HgNvnIVbHg5lY2SzgExy72DUNCyi20An6OGNqWw4CIQDkDMDTmPd6p/aHAtYP8Jh7z/4Nb/09LxpNXQS72ouixA=="
    private static let euRoot = "MIIC0zCCAnmgAwIBAgIUXRXxkLbUM6+njr/XT0IIw/HA/uowCgYIKoZIzj0EAwMwVzEZMBcGA1UEAwwQUElEIElzc3VlciBDQSAwMjEtMCsGA1UECgwkRVVESSBXYWxsZXQgUmVmZXJlbmNlIEltcGxlbWVudGF0aW9uMQswCQYDVQQGEwJFVTAeFw0yNTA0MDkwMDAzMzBaFw0zNDA3MDYwMDAzMjlaMFcxGTAXBgNVBAMMEFBJRCBJc3N1ZXIgQ0EgMDIxLTArBgNVBAoMJEVVREkgV2FsbGV0IFJlZmVyZW5jZSBJbXBsZW1lbnRhdGlvbjELMAkGA1UEBhMCRVUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARkqdLmwIlv+SSWr00tAIrt7EAMztgd3w9qA6qEm16yVfsLcyx2f4oIWuH45wa37J9GoNWpdeo27VoSoNMCzxOYo4IBITCCAR0wEgYDVR0TAQH/BAgwBgEB/wIBADAfBgNVHSMEGDAWgBRCUFC+ELgQ8J1EXI2/qxAI7ifcSTATBgNVHSUEDDAKBggrgQICAAABBzBDBgNVHR8EPDA6MDigNqA0hjJodHRwczovL3ByZXByb2QucGtpLmV1ZGl3LmRldi9jcmwvcGlkX0NBX0VVXzAyLmNybDAdBgNVHQ4EFgQUQlBQvhC4EPCdRFyNv6sQCO4n3EkwDgYDVR0PAQH/BAQDAgEGMF0GA1UdEgRWMFSGUmh0dHBzOi8vZ2l0aHViLmNvbS9ldS1kaWdpdGFsLWlkZW50aXR5LXdhbGxldC9hcmNoaXRlY3R1cmUtYW5kLXJlZmVyZW5jZS1mcmFtZXdvcmswCgYIKoZIzj0EAwMDSAAwRQIhAIavYfC5o0VVLKfgTKkzzWgc09hzDMsCl3O2le2sQfG7AiA2soqAN5gtUOLQKWK00DUz22EW79rvaV+VJPvfdQeokA=="

    private let isEnabled: @Sendable (EUDITestMode.Category) -> Bool

    init(isEnabled: @escaping @Sendable (EUDITestMode.Category) -> Bool = EUDITestMode.isEnabled) {
        self.isEnabled = isEnabled
    }

    func supports(issuer: URL, vct: String) -> Bool {
        issuer.absoluteString == Self.issuerIdentifier && Self.categoriesByVCT[vct] != nil
    }

    func trustedRoots(issuer: URL, vct: String, now: Date) throws -> [Data] {
        guard supports(issuer: issuer, vct: vct), let category = Self.categoriesByVCT[vct] else {
            throw WalletError.invalidIssuer("No EUDI test certificate trust policy applies to this credential.")
        }
        guard isEnabled(category) else { throw WalletError.unsupportedIssuerCertificateTrust }
        let lu = try Self.pinnedRoot(Self.luRoot,
                                     fingerprint: "7d8713f9aeaa821244a22e3559e095e5bb84cce6d732840a9d371055a3059178",
                                     now: now)
        if category == .pid {
            let eu = try Self.pinnedRoot(Self.euRoot,
                                         fingerprint: "3b0a223e8748f3c42217298ad905ecf1a104e73cd2c54ff21da16fda8070b297",
                                         now: now)
            return [lu, eu]
        }
        return [lu]
    }

    private static func pinnedRoot(_ encoded: String, fingerprint: String, now: Date) throws -> Data {
        guard let der = Data(base64Encoded: encoded),
              SecCertificateCreateWithData(nil, der as CFData) != nil,
              Data(SHA256.hash(data: der)).map({ String(format: "%02x", $0) }).joined() == fingerprint,
              EUDITestLoTEVerifier.isWithinValidity(der, now: now) else {
            throw WalletError.invalidIssuer("An EUDI test CA certificate is missing or expired.")
        }
        return der
    }
}

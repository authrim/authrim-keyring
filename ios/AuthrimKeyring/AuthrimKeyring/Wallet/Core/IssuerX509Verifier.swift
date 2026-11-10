import Foundation
import Security

/// Ecosystem policy supplies trust anchors for a credential issuer and credential type.
/// An x5c header is evidence to check, never a source of trust anchors by itself.
nonisolated protocol IssuerCertificateTrustSource: Sendable {
    func supports(issuer: URL, vct: String) -> Bool
    func trustedRoots(for chainDER: [Data], issuer: URL, vct: String) async throws -> [Data]
}

/// Resolves an SD-JWT VC issuer signing key from its x5c certificate chain (HAIP 6.1.1).
/// The returned key has already been checked against an independent CA anchor and the JWT
/// signature. SDJWTVerifier then checks the credential's issuer, type, holder binding and claims.
nonisolated enum IssuerX509Verifier {
    static func signingKey(
        of parsed: ParsedSDJWT, issuer: URL, vct: String,
        trustSource: any IssuerCertificateTrustSource, now: Date
    ) async throws -> PublicJWK {
        guard trustSource.supports(issuer: issuer, vct: vct) else {
            throw WalletError.invalidIssuer("No certificate trust policy is configured for this issuer.")
        }
        let chainDER = try certificateChain(of: parsed)
        let trustedRoots = try await trustSource.trustedRoots(
            for: chainDER, issuer: issuer, vct: vct)
        return try validate(parsed, issuer: issuer, chainDER: chainDER,
                            trustedRootDER: trustedRoots, now: now)
    }

    static func certificateChain(of parsed: ParsedSDJWT) throws -> [Data] {
        guard let parts = JWS.parse(parsed.issuerJWT),
              parts.header["alg"] as? String == "ES256",
              parts.header["typ"] as? String == "dc+sd-jwt",
              parts.header["crit"] == nil,
              let encoded = parts.header["x5c"] as? [String],
              (1...8).contains(encoded.count)
        else { throw WalletError.invalidCredential("The HAIP credential has no supported issuer certificate chain.") }
        let certificates = encoded.compactMap(certificateDER)
        guard certificates.count == encoded.count else {
            throw WalletError.invalidCredential("The issuer certificate chain is malformed.")
        }
        return certificates
    }

    static func validate(
        _ parsed: ParsedSDJWT, issuer: URL, chainDER: [Data],
        trustedRootDER: [Data], now: Date
    ) throws -> PublicJWK {
        guard (1...8).contains(chainDER.count), !trustedRootDER.isEmpty,
              !chainDER.contains(where: trustedRootDER.contains),
              let chain = certificates(chainDER),
              let roots = certificates(trustedRootDER)
        else { throw WalletError.invalidCredential("The issuer certificate has no independent trust anchor.") }

        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(chain as CFArray, SecPolicyCreateBasicX509(), &trust) == errSecSuccess,
              let trust,
              SecTrustSetAnchorCertificates(trust, roots as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
              SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
              SecTrustSetVerifyDate(trust, now as CFDate) == errSecSuccess,
              SecTrustEvaluateWithError(trust, nil),
              SecTrustGetCertificateCount(trust) >= 2
        else { throw WalletError.invalidCredential("The issuer certificate is not trusted.") }

        guard IssuerCertificateNames.matches(issuer: issuer, in: chainDER[0]) else {
            throw WalletError.invalidCredential("The issuer certificate does not identify this issuer.")
        }

        guard let signingKey = SecCertificateCopyKey(chain[0]),
              let point = SecKeyCopyExternalRepresentation(signingKey, nil) as Data?,
              let jwk = PublicJWK(x963: point),
              let key = jwk.cryptoKey,
              let parts = JWS.parse(parsed.issuerJWT),
              parts.header["alg"] as? String == "ES256",
              parts.header["typ"] as? String == "dc+sd-jwt",
              parts.header["crit"] == nil,
              JWS.verifyES256(parts, with: key)
        else { throw WalletError.invalidCredential("The issuer certificate does not sign this credential.") }
        return jwk
    }

    private static func certificates(_ encoded: [Data]) -> [SecCertificate]? {
        let result = encoded.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        return result.count == encoded.count ? result : nil
    }

    /// JOSE x5c uses standard Base64, not Base64URL. Accept omitted terminal padding only.
    private static func certificateDER(_ encoded: String) -> Data? {
        guard !encoded.isEmpty, encoded.utf8.count <= 16 * 1024 else { return nil }
        let bare = encoded.prefix(while: { $0 != "=" })
        let suppliedPadding = encoded.dropFirst(bare.count)
        let alphabet = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        guard suppliedPadding.count <= 2, suppliedPadding.allSatisfy({ $0 == "=" }),
              bare.unicodeScalars.allSatisfy(alphabet.contains), bare.count % 4 != 1
        else { return nil }
        let padded = String(bare) + String(repeating: "=", count: (4 - bare.count % 4) % 4)
        return Data(base64Encoded: padded)
    }
}

/// iOS does not expose SecCertificateCopyValues. Read only the bounded DER path to the
/// SubjectAlternativeName extension; all other certificate checks are left to SecTrust.
/// URI SANs bind the full issuer identifier. DNS SANs bind root-path issuers only.
private nonisolated enum IssuerCertificateNames {
    static func matches(issuer: URL, in certificateDER: Data) -> Bool {
        let bytes = Array(certificateDER)
        var document = DERReader(bytes)
        guard let certificate = document.read(tag: 0x30), document.isAtEnd else { return false }
        var outer = DERReader(bytes, within: certificate)
        guard let tbs = outer.read(tag: 0x30), outer.read(tag: 0x30) != nil,
              outer.read(tag: 0x03) != nil, outer.isAtEnd else { return false }
        var fields = DERReader(bytes, within: tbs)
        if fields.nextTag == 0xA0 { guard fields.read(tag: 0xA0) != nil else { return false } }
        for tag: UInt8 in [0x02, 0x30, 0x30, 0x30, 0x30, 0x30] {
            guard fields.read(tag: tag) != nil else { return false }
        }
        var extensions: Range<Int>?
        while !fields.isAtEnd {
            guard let element = fields.read() else { return false }
            switch element.tag {
            case 0x81, 0x82: break // optional issuer/subject unique IDs
            case 0xA3:
                guard extensions == nil else { return false }
                extensions = element.value
            default: return false
            }
        }
        guard let extensions else { return false }
        var explicit = DERReader(bytes, within: extensions)
        guard let sequence = explicit.read(tag: 0x30), explicit.isAtEnd else { return false }
        var items = DERReader(bytes, within: sequence)
        var seenSAN = false
        var matched = false
        while !items.isAtEnd {
            guard let item = items.read(tag: 0x30) else { return false }
            var ext = DERReader(bytes, within: item)
            guard let oid = ext.read(tag: 0x06) else { return false }
            if ext.nextTag == 0x01 { guard ext.read(tag: 0x01) != nil else { return false } }
            guard let value = ext.read(tag: 0x04), ext.isAtEnd else { return false }
            if Array(bytes[oid]) == [0x55, 0x1D, 0x11] { // 2.5.29.17
                guard !seenSAN, let hasIssuer = matches(issuer: issuer, namesDER: bytes, range: value) else { return false }
                seenSAN = true
                matched = hasIssuer
            }
        }
        return seenSAN && matched
    }

    private static func matches(issuer: URL, namesDER bytes: [UInt8], range: Range<Int>) -> Bool? {
        var encoded = DERReader(bytes, within: range)
        guard let names = encoded.read(tag: 0x30), encoded.isAtEnd else { return nil }
        var entries = DERReader(bytes, within: names)
        var sawURI = false
        var matchedURI = false
        var matchedDNS = false
        while !entries.isAtEnd {
            guard let name = entries.read() else { return nil }
            switch name.tag {
            case 0x86: // uniformResourceIdentifier, IA5String
                guard let value = String(bytes: bytes[name.value], encoding: .ascii) else { return nil }
                sawURI = true
                if value == issuer.absoluteString { matchedURI = true }
            case 0x82: // dNSName, IA5String
                guard let value = String(bytes: bytes[name.value], encoding: .ascii) else { return nil }
                if issuer.path.isEmpty || issuer.path == "/",
                   issuer.query == nil, issuer.fragment == nil,
                   value.lowercased() == issuer.host?.lowercased() {
                    matchedDNS = true
                }
            default: break
            }
        }
        return matchedURI || (!sawURI && matchedDNS)
    }

    private struct DERReader {
        let bytes: [UInt8]
        let end: Int
        var position: Int

        init(_ bytes: [UInt8], within range: Range<Int>? = nil) {
            self.bytes = bytes
            position = range?.lowerBound ?? 0
            end = range?.upperBound ?? bytes.count
        }

        var isAtEnd: Bool { position == end }
        var nextTag: UInt8? { position < end ? bytes[position] : nil }

        mutating func read(tag expected: UInt8) -> Range<Int>? {
            guard let element = read(), element.tag == expected else { return nil }
            return element.value
        }

        mutating func read() -> (tag: UInt8, value: Range<Int>)? {
            guard position + 2 <= end else { return nil }
            let tag = bytes[position]
            position += 1
            let first = bytes[position]
            position += 1
            let length: Int
            if first & 0x80 == 0 {
                length = Int(first)
            } else {
                let octets = Int(first & 0x7F)
                guard (1...4).contains(octets), position + octets <= end,
                      bytes[position] != 0 else { return nil }
                var result = 0
                for _ in 0..<octets {
                    result = (result << 8) | Int(bytes[position])
                    position += 1
                }
                guard result >= 128 else { return nil }
                length = result
            }
            guard length <= end - position else { return nil }
            let value = position..<(position + length)
            position += length
            return (tag, value)
        }
    }
}

/// The public European Commission sandbox's validator is used only for the exact EUDI test issuer.
/// Its verdict and CA anchor are checked locally against the credential's x5c chain. This is an
/// interoperability policy, not a production trust framework for arbitrary issuers.
nonisolated struct EUDITestIssuerCertificateTrustSource: IssuerCertificateTrustSource {
    private static let issuerIdentifier = "https://issuer.eudiw.dev"
    /// This is an issuer-scoped interoperability policy for the EUDI sandbox. These exact SD-JWT
    /// types use its PubEAA trust context, followed by local chain, issuer and signature checks.
    /// Keep the VCT allowlist independent of the certificate supplied in the credential.
    private static let verificationContexts: [String: String] = [
        "urn:eu.europa.ec.eudi:diploma:1:1": "PubEAA",
        "urn:eu.europa.ec.eudi:learning:credential:1": "PubEAA",
        "urn:eudi:ehic:1": "PubEAA",
        "urn:eu.europa.ec.eudi:hiid:1": "PubEAA",
    ]
    private static let validatorOrigin = URL(string: "https://trust-validator.eudiw.dev")!
    private static let trustEndpoint = URL(string: "https://trust-validator.eudiw.dev/trust")!

    private let http: WalletHTTP

    init(http: WalletHTTP = WalletHTTP()) { self.http = http }

    func supports(issuer: URL, vct: String) -> Bool {
        issuer.absoluteString == Self.issuerIdentifier && Self.verificationContexts[vct] != nil
    }

    func trustedRoots(for chainDER: [Data], issuer: URL, vct: String) async throws -> [Data] {
        guard supports(issuer: issuer, vct: vct),
              let verificationContext = Self.verificationContexts[vct],
              (1...8).contains(chainDER.count) else {
            throw WalletError.invalidIssuer("No EUDI test certificate trust policy applies to this credential.")
        }
        // Do not fall back to a broader context when the validator rejects the chain.
        let body = try JSONSerialization.data(withJSONObject: [
            "chain": chainDER.map { $0.base64EncodedString() },
            "verificationContext": verificationContext,
        ])
        let response = try await http.send(
            Self.trustEndpoint, method: "POST",
            headers: ["Content-Type": "application/json"], body: body,
            origin: Self.validatorOrigin)
        guard response.status == 200,
              let object = (try? JSONSerialization.jsonObject(with: response.data)) as? [String: Any],
              object["trusted"] as? Bool == true,
              let encodedAnchor = object["trustAnchor"] as? String,
              let anchor = decodeAnchor(encodedAnchor),
              !chainDER.contains(anchor),
              SecCertificateCreateWithData(nil, anchor as CFData) != nil
        else { throw WalletError.invalidCredential("The EUDI test issuer certificate is not trusted.") }
        return [anchor]
    }

    private func decodeAnchor(_ encoded: String) -> Data? {
        guard !encoded.isEmpty, encoded.utf8.count <= 16 * 1024 else { return nil }
        let bare = encoded.prefix(while: { $0 != "=" })
        let padding = encoded.dropFirst(bare.count)
        let alphabet = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        guard padding.count <= 2, padding.allSatisfy({ $0 == "=" }),
              bare.unicodeScalars.allSatisfy(alphabet.contains), bare.count % 4 != 1 else { return nil }
        return Data(base64Encoded: String(bare) + String(repeating: "=", count: (4 - bare.count % 4) % 4))
    }
}

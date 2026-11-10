import CryptoKit
import Foundation
import Security

/// Supplied out of band by a trusted operator. Neither value may be learned from the LoTE JWT,
/// its x5c header, the LoTE download endpoint, or a trust-validator response.
nonisolated struct EUDITestLoTESignerPins: Sendable {
    let signerSHA256: Data
    let rootCertificatesDER: [Data]
    /// Authenticated alongside the signer pins to reject first-install replay of older lists.
    let minimumSequence: Int
}

nonisolated struct EUDITestLoTESnapshot: Sendable {
    let sequence: Int
    let issuedAt: Date
    let nextUpdate: Date
    let issuanceRootsDER: [Data]
}

/// Verifies the EUDI test PubEAA LoTE itself before any certificate from it becomes a trust anchor.
/// The list does not grant rights to issue particular VCTs; that is a separate issuer policy.
nonisolated enum EUDITestLoTEVerifier {
    static let url = URL(string: "https://trustedlist.serviceproviders.eudiw.dev/LOTE/json/PubEAAProviders.jwt")!
    static let maxBytes = 128 * 1024
    private static let listType = "http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList"
    private static let issuanceType = "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance"
    private static let notifiedStatus = "http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/notified"

    static func verify(_ jwt: String, pins: EUDITestLoTESignerPins, now: Date) throws -> EUDITestLoTESnapshot {
        guard !jwt.isEmpty, jwt.utf8.count <= maxBytes,
              pins.signerSHA256.count == 32, !pins.rootCertificatesDER.isEmpty,
              pins.minimumSequence > 0,
              let parts = JWS.parse(jwt),
              parts.header["alg"] as? String == "ES256",
              parts.header["typ"] as? String == "JOSE+JSON",
              parts.header["crit"] == nil,
              let encodedChain = parts.header["x5c"] as? [String],
              (1...8).contains(encodedChain.count),
              let chainDER = decodeChain(encodedChain),
              Data(SHA256.hash(data: chainDER[0])) == pins.signerSHA256,
              !chainDER.contains(where: pins.rootCertificatesDER.contains),
              let chain = certificates(chainDER),
              let roots = certificates(pins.rootCertificatesDER),
              pins.rootCertificatesDER.allSatisfy({ isWithinValidity($0, now: now) })
        else { throw WalletError.invalidIssuer("The EUDI test trust list has no independently trusted signer.") }

        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(chain as CFArray, SecPolicyCreateBasicX509(), &trust) == errSecSuccess,
              let trust,
              SecTrustSetAnchorCertificates(trust, roots as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
              SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
              SecTrustSetVerifyDate(trust, now as CFDate) == errSecSuccess,
              SecTrustEvaluateWithError(trust, nil),
              SecTrustGetCertificateCount(trust) >= 2,
              isWithinValidity(chainDER[0], now: now),
              let signingKey = SecCertificateCopyKey(chain[0]),
              let point = SecKeyCopyExternalRepresentation(signingKey, nil) as Data?,
              let jwk = PublicJWK(x963: point),
              let key = jwk.cryptoKey,
              JWS.verifyES256(parts, with: key)
        else { throw WalletError.invalidIssuer("The EUDI test trust list signature or signer certificate is invalid.") }

        guard let lote = parts.payload["LoTE"] as? [String: Any],
              let info = lote["ListAndSchemeInformation"] as? [String: Any],
              info["LoTEVersionIdentifier"] as? Int == 1,
              info["LoTEType"] as? String == listType,
              info["SchemeTerritory"] as? String == "EU",
              let distributionPoints = info["DistributionPoints"] as? [String],
              distributionPoints.contains(url.absoluteString),
              let sequence = info["LoTESequenceNumber"] as? Int,
              sequence >= pins.minimumSequence,
              let issueText = info["ListIssueDateTime"] as? String,
              let updateText = info["NextUpdate"] as? String,
              let issuedAt = date(issueText), let nextUpdate = date(updateText),
              issuedAt <= now.addingTimeInterval(300),
              nextUpdate > issuedAt,
              nextUpdate.timeIntervalSince(issuedAt) <= 366 * 86_400,
              let headerIAT = parts.header["iat"] as? Int,
              abs(Date(timeIntervalSince1970: TimeInterval(headerIAT)).timeIntervalSince(issuedAt)) <= 300,
              Date(timeIntervalSince1970: TimeInterval(headerIAT)) <= now.addingTimeInterval(300),
              let entities = lote["TrustedEntitiesList"] as? [[String: Any]],
              (1...200).contains(entities.count)
        else { throw WalletError.invalidIssuer("The EUDI test trust list metadata is invalid.") }

        var anchors = Set<Data>()
        for entity in entities {
            guard let services = entity["TrustedEntityServices"] as? [[String: Any]],
                  services.count <= 1_000 else {
                throw WalletError.invalidIssuer("The EUDI test trust list services are malformed.")
            }
            for service in services {
                guard let item = service["ServiceInformation"] as? [String: Any],
                      let type = item["ServiceTypeIdentifier"] as? String,
                      let status = item["ServiceStatus"] as? String,
                      let startText = item["StatusStartingTime"] as? String,
                      let start = date(startText) else {
                    throw WalletError.invalidIssuer("The EUDI test trust list service is malformed.")
                }
                guard type == issuanceType, status == notifiedStatus, start <= now else { continue }
                guard let identity = item["ServiceDigitalIdentity"] as? [String: Any],
                      let listed = identity["X509Certificates"] as? [[String: Any]],
                      (1...8).contains(listed.count) else {
                    throw WalletError.invalidIssuer("The EUDI test trust list issuance certificate is missing.")
                }
                for certificate in listed {
                    guard let encoded = certificate["val"] as? String,
                          let der = decodeCertificate(encoded),
                          let parsed = SecCertificateCreateWithData(nil, der as CFData),
                          isWithinValidity(der, now: now) else {
                        throw WalletError.invalidIssuer("The EUDI test trust list contains an invalid issuance certificate.")
                    }
                    anchors.insert(der)
                    guard anchors.count <= 256 else {
                        throw WalletError.invalidIssuer("The EUDI test trust list contains too many issuance certificates.")
                    }
                }
            }
        }
        guard !anchors.isEmpty else {
            throw WalletError.invalidIssuer("The EUDI test trust list has no active PubEAA issuance service.")
        }
        return EUDITestLoTESnapshot(
            sequence: sequence, issuedAt: issuedAt, nextUpdate: nextUpdate,
            issuanceRootsDER: Array(anchors))
    }

    private static func certificates(_ der: [Data]) -> [SecCertificate]? {
        guard (1...8).contains(der.count) else { return nil }
        let parsed = der.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        return parsed.count == der.count ? parsed : nil
    }

    /// iOS 17 has no SecCertificateCopyNotValidBeforeDate/AfterDate. Read only the bounded
    /// TBSCertificate validity sequence; SecTrust performs the full PKIX checks separately.
    static func isWithinValidity(_ der: Data, now: Date) -> Bool {
        let bytes = Array(der)
        var document = DERReader(bytes)
        guard let certificate = document.read(tag: 0x30), document.isAtEnd else { return false }
        var fields = DERReader(bytes, within: certificate)
        guard let tbs = fields.read(tag: 0x30) else { return false }
        var tbsFields = DERReader(bytes, within: tbs)
        if tbsFields.nextTag == 0xA0 { guard tbsFields.read(tag: 0xA0) != nil else { return false } }
        guard tbsFields.read(tag: 0x02) != nil, tbsFields.read(tag: 0x30) != nil,
              tbsFields.read(tag: 0x30) != nil,
              let validity = tbsFields.read(tag: 0x30) else { return false }
        var dates = DERReader(bytes, within: validity)
        guard let start = dates.read(), let end = dates.read(), dates.isAtEnd,
              let from = certificateDate(start, in: bytes),
              let until = certificateDate(end, in: bytes) else { return false }
        return from <= now && now < until
    }

    private static func certificateDate(_ field: (tag: UInt8, value: Range<Int>), in bytes: [UInt8]) -> Date? {
        guard field.tag == 0x17 || field.tag == 0x18,
              let text = String(bytes: bytes[field.value], encoding: .ascii),
              text.hasSuffix("Z") else { return nil }
        let general = field.tag == 0x18
        guard text.count == (general ? 15 : 13), text.dropLast().allSatisfy({ $0.isASCII && $0.isNumber }) else {
            return nil
        }
        let digits = Array(text.utf8)
        func value(_ start: Int, _ count: Int) -> Int {
            digits[start..<(start + count)].reduce(0) { $0 * 10 + Int($1 - 48) }
        }
        let year = general ? value(0, 4) : (value(0, 2) >= 50 ? 1900 + value(0, 2) : 2000 + value(0, 2))
        let offset = general ? 4 : 2
        let parts = (year, value(offset, 2), value(offset + 2, 2),
                     value(offset + 4, 2), value(offset + 6, 2), value(offset + 8, 2))
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        let components = DateComponents(
            calendar: calendar, timeZone: calendar.timeZone, year: parts.0, month: parts.1,
            day: parts.2, hour: parts.3, minute: parts.4, second: parts.5)
        guard let date = calendar.date(from: components) else { return nil }
        let checked = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        guard checked.year == parts.0, checked.month == parts.1, checked.day == parts.2,
              checked.hour == parts.3, checked.minute == parts.4, checked.second == parts.5 else { return nil }
        return date
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

    private static func decodeChain(_ encoded: [String]) -> [Data]? {
        let result = encoded.compactMap(decodeCertificate)
        return result.count == encoded.count ? result : nil
    }

    private static func decodeCertificate(_ encoded: String) -> Data? {
        guard !encoded.isEmpty, encoded.utf8.count <= 16 * 1024 else { return nil }
        let bare = encoded.prefix(while: { $0 != "=" })
        let padding = encoded.dropFirst(bare.count)
        let alphabet = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        guard padding.count <= 2, padding.allSatisfy({ $0 == "=" }),
              bare.unicodeScalars.allSatisfy(alphabet.contains), bare.count % 4 != 1 else { return nil }
        return Data(base64Encoded: String(bare) + String(repeating: "=", count: (4 - bare.count % 4) % 4))
    }

    private static func date(_ value: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        if let date = formatter.date(from: value) { return date }
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: value)
    }
}

nonisolated struct EUDITestLoTERecord: Codable, Identifiable, Sendable {
    static let identifier = UUID(uuidString: "5207EE4E-4C71-4795-899C-62437A58FB48")!
    let id: UUID
    let jwt: String
    let sequence: Int
    let issuedAt: Date
    let checkedAt: Date

    init(jwt: String, snapshot: EUDITestLoTESnapshot, checkedAt: Date) {
        id = Self.identifier
        self.jwt = jwt
        sequence = snapshot.sequence
        issuedAt = snapshot.issuedAt
        self.checkedAt = checkedAt
    }
}

nonisolated protocol EUDITestLoTERecordStore: Sendable {
    func load() throws -> EUDITestLoTERecord?
    func save(_ record: EUDITestLoTERecord) throws
}

/// A separate, device-only Keychain service. Never synced or exported with credentials/backups.
nonisolated struct KeychainEUDITestLoTERecordStore: EUDITestLoTERecordStore {
    private static let service = "com.authrim.keyring.trust.eudi-test.pubeaa"

    func load() throws -> EUDITestLoTERecord? {
        let stored = try KeychainStore(service: Self.service)
            .loadAllCountingSkipped(EUDITestLoTERecord.self, from: .device)
        guard stored.skipped == 0, stored.items.count <= 1,
              stored.items.allSatisfy({ $0.id == EUDITestLoTERecord.identifier }) else {
            throw WalletError.invalidIssuer("The saved EUDI test trust list is corrupt.")
        }
        return stored.items.first
    }

    func save(_ record: EUDITestLoTERecord) throws {
        try KeychainStore(service: Self.service).save(record, to: .device)
    }
}

/// Refreshes on first use, once per day, and near NextUpdate. Network failures may use only a
/// still-valid, reverified record. A malformed, bad-signature, or rolled-back response is fatal.
actor EUDITestLoTECache {
    private let http: WalletHTTP
    private let pins: EUDITestLoTESignerPins?
    private let recordStore: any EUDITestLoTERecordStore
    private let now: @Sendable () -> Date
    private var loaded = false
    private var record: EUDITestLoTERecord?

    init(
        http: WalletHTTP, pins: EUDITestLoTESignerPins?,
        recordStore: any EUDITestLoTERecordStore,
        now: @escaping @Sendable () -> Date
    ) {
        self.http = http
        self.pins = pins
        self.recordStore = recordStore
        self.now = now
    }

    func snapshot() async throws -> EUDITestLoTESnapshot {
        // The public EUDI test environment has not published an independently authenticated
        // LoTE signing key for this app. Until an out-of-band pin is provisioned, fail closed.
        guard let pins else { throw WalletError.unsupportedIssuerCertificateTrust }
        if !loaded {
            record = try recordStore.load()
            loaded = true
        }
        let currentTime = now()
        let oldSnapshot = try verifiedSavedSnapshot(pins: pins, at: currentTime)
        let needsRefresh: Bool
        if let record, let oldSnapshot {
            needsRefresh = currentTime.timeIntervalSince(record.checkedAt) >= 24 * 3_600 ||
                oldSnapshot.nextUpdate <= currentTime.addingTimeInterval(3_600)
        } else {
            needsRefresh = true
        }
        if needsRefresh {
            let response: WalletHTTPResponse
            do {
                response = try await http.send(EUDITestLoTEVerifier.url, maxBytes: EUDITestLoTEVerifier.maxBytes,
                                               origin: EUDITestLoTEVerifier.url, idempotentRead: true)
            } catch is CancellationError {
                throw CancellationError()
            } catch let error as WalletError {
                guard case .network = error else { throw error }
                let fallbackTime = now()
                if let latest = try verifiedSavedSnapshot(pins: pins, at: fallbackTime),
                   fallbackTime < latest.nextUpdate { return latest }
                throw error
            } catch let error as URLError {
                // Another actor turn may have saved a newer list while this request was suspended.
                // Re-read it, and use the clock at the time of the fallback decision.
                let fallbackTime = now()
                if let latest = try verifiedSavedSnapshot(pins: pins, at: fallbackTime),
                   fallbackTime < latest.nextUpdate { return latest }
                throw error
            }
            let responseTime = now()
            if (500...599).contains(response.status) {
                if let latest = try verifiedSavedSnapshot(pins: pins, at: responseTime),
                   responseTime < latest.nextUpdate { return latest }
                throw WalletError.network("The EUDI test trust list could not be refreshed.")
            }
            guard response.status == 200,
                  response.data.count <= EUDITestLoTEVerifier.maxBytes,
                  let jwt = String(data: response.data, encoding: .utf8) else {
                throw WalletError.invalidIssuer("The EUDI test trust list update is invalid.")
            }
            let newSnapshot = try EUDITestLoTEVerifier.verify(jwt, pins: pins, now: responseTime)
            guard responseTime < newSnapshot.nextUpdate else {
                throw WalletError.invalidIssuer("The EUDI test trust list update has expired.")
            }
            if let record {
                guard newSnapshot.sequence >= record.sequence,
                      newSnapshot.issuedAt >= record.issuedAt,
                      newSnapshot.sequence != record.sequence || jwt == record.jwt else {
                    throw WalletError.invalidIssuer("The EUDI test trust list update rolled back or changed at the same sequence.")
                }
            }
            let next = EUDITestLoTERecord(jwt: jwt, snapshot: newSnapshot, checkedAt: responseTime)
            try recordStore.save(next)
            record = next
            return newSnapshot
        }
        guard let oldSnapshot, currentTime < oldSnapshot.nextUpdate else {
            throw WalletError.invalidIssuer("The EUDI test trust list has expired.")
        }
        return oldSnapshot
    }

    private func verifiedSavedSnapshot(
        pins: EUDITestLoTESignerPins, at time: Date
    ) throws -> EUDITestLoTESnapshot? {
        guard let record else { return nil }
        guard time.addingTimeInterval(300) >= record.checkedAt else {
            throw WalletError.invalidIssuer("The device clock moved behind the verified trust list state.")
        }
        let verified = try EUDITestLoTEVerifier.verify(record.jwt, pins: pins, now: time)
        guard verified.sequence == record.sequence, verified.issuedAt == record.issuedAt else {
            throw WalletError.invalidIssuer("The saved EUDI test trust list state is inconsistent.")
        }
        return verified
    }
}

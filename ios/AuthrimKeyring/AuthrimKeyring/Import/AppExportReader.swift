import Foundation

/// Reads accounts exported by other authenticator apps: a list of `otpauth://`
/// key URIs (as Ente Auth and others export), or an unencrypted Aegis, 2FAS or
/// Bitwarden file.
nonisolated enum AppExportReader {
    static let maximumFileSize = 5 * 1024 * 1024

    static func read(_ data: Data) throws(ImportError) -> ImportedAccounts {
        guard data.count <= maximumFileSize else { throw .tooLarge }
        if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            if object["db"] != nil {
                return try readAegis(object)
            }
            if object["services"] != nil || object["servicesEncrypted"] != nil {
                return try readTwoFAS(object)
            }
            if object["items"] != nil || object["encrypted"] as? Bool == true {
                return try readBitwarden(object)
            }
            throw .unrecognized
        }
        guard let text = String(data: data, encoding: .utf8) else { throw .unrecognized }
        return try readKeyURIs(text)
    }

    /// One key URI per line, as many apps export. Google Authenticator transfer
    /// links are accepted too.
    static func readKeyURIs(_ text: String) throws(ImportError) -> ImportedAccounts {
        guard text.utf8.count <= maximumFileSize else { throw .tooLarge }
        var result = ImportedAccounts()
        var recognized = false
        // Transfer codes are checked as a set, like when they are scanned one by one.
        var transfer: MigrationProgress?
        for line in text.split(whereSeparator: \.isNewline) {
            let entry = line.trimmingCharacters(in: .whitespaces)
            let lowercased = entry.lowercased()
            if lowercased.hasPrefix("otpauth-migration:") {
                recognized = true
                let batch = try GoogleAuthMigration.parse(entry)
                if transfer == nil {
                    transfer = MigrationProgress(first: batch)
                } else {
                    try transfer?.add(batch)
                }
            } else if lowercased.hasPrefix("otpauth:") {
                recognized = true
                do {
                    result.accounts.append(try OTPAuthURI.parse(entry))
                } catch {
                    result.skip(label(of: entry), reason: error.localizedDescription)
                }
            }
            guard result.accounts.count + result.skipped.count <= ImportedAccounts.maximumEntries else { throw .tooLarge }
        }
        guard recognized else { throw .unrecognized }
        if let transfer {
            guard transfer.isComplete else {
                throw .incompleteTransfer(scanned: transfer.scannedCount, total: transfer.size)
            }
            result.append(contentsOf: transfer.accounts)
        }
        guard result.accounts.count + result.skipped.count <= ImportedAccounts.maximumEntries else { throw .tooLarge }
        return result
    }

    private static func readAegis(_ object: [String: Any]) throws(ImportError) -> ImportedAccounts {
        // An encrypted vault keeps `db` as a Base64 string.
        guard let database = object["db"] as? [String: Any] else { throw .encrypted(app: "Aegis") }
        guard let entries = database["entries"] as? [[String: Any]] else { throw .damaged }
        guard entries.count <= ImportedAccounts.maximumEntries else { throw .tooLarge }
        var result = ImportedAccounts()
        for entry in entries {
            let issuer = entry["issuer"] as? String ?? ""
            let name = entry["name"] as? String ?? ""
            let info = entry["info"] as? [String: Any] ?? [:]
            let type = (entry["type"] as? String ?? "").lowercased()
            addEntry(
                to: &result,
                issuer: issuer,
                accountName: name,
                kind: kind(type, counter: info["counter"]),
                typeName: type.uppercased(),
                secret: info["secret"] as? String,
                algorithm: info["algo"] as? String,
                digits: info["digits"] as? Int,
                period: info["period"] as? Int
            )
        }
        return result
    }

    private static func readTwoFAS(_ object: [String: Any]) throws(ImportError) -> ImportedAccounts {
        // Checked first: a file may carry encrypted services next to plain ones.
        if let encrypted = object["servicesEncrypted"] as? String, !encrypted.isEmpty {
            throw .encrypted(app: "2FAS")
        }
        let services = object["services"] as? [[String: Any]] ?? []
        guard services.count <= ImportedAccounts.maximumEntries else { throw .tooLarge }
        var result = ImportedAccounts()
        for service in services {
            let otp = service["otp"] as? [String: Any] ?? [:]
            let type = (otp["tokenType"] as? String ?? "TOTP").uppercased()
            addEntry(
                to: &result,
                issuer: otp["issuer"] as? String ?? service["name"] as? String ?? "",
                accountName: otp["account"] as? String ?? otp["label"] as? String ?? "",
                kind: kind(type, counter: otp["counter"]),
                typeName: type,
                secret: service["secret"] as? String,
                algorithm: otp["algorithm"] as? String,
                digits: otp["digits"] as? Int,
                period: otp["period"] as? Int
            )
        }
        return result
    }

    /// Bitwarden keeps a key URI, a bare Base32 key, or `steam://` and a key with
    /// each login; the login's own addresses become the card's websites.
    private static func readBitwarden(_ object: [String: Any]) throws(ImportError) -> ImportedAccounts {
        if object["encrypted"] as? Bool == true { throw .encrypted(app: "Bitwarden") }
        guard let items = object["items"] as? [[String: Any]] else { throw .damaged }
        guard items.count <= ImportedAccounts.maximumEntries else { throw .tooLarge }
        var result = ImportedAccounts()
        for item in items {
            guard let login = item["login"] as? [String: Any],
                  let totp = (login["totp"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines),
                  !totp.isEmpty
            else { continue }
            let issuer = item["name"] as? String ?? ""
            let accountName = login["username"] as? String ?? ""
            let before = result.accounts.count
            if totp.lowercased().hasPrefix("otpauth:") {
                do {
                    var account = try OTPAuthURI.parse(totp)
                    // The login's name is what the user knows it by.
                    if !issuer.isEmpty { account.issuer = issuer }
                    if account.accountName.isEmpty { account.accountName = accountName }
                    result.add(account, label: entryLabel(issuer, accountName))
                } catch {
                    result.skip(entryLabel(issuer, accountName), reason: error.localizedDescription)
                }
            } else {
                let isSteam = totp.lowercased().hasPrefix("steam://")
                addEntry(
                    to: &result,
                    issuer: issuer,
                    accountName: accountName,
                    kind: isSteam ? .steam : .totp,
                    typeName: "",
                    secret: isSteam ? String(totp.dropFirst("steam://".count)) : totp,
                    algorithm: nil,
                    digits: nil,
                    period: nil
                )
            }
            guard result.accounts.count > before, let account = result.accounts.last else { continue }
            let uris = (login["uris"] as? [[String: Any]] ?? []).compactMap { $0["uri"] as? String }
            var websites: [String] = []
            for uri in uris {
                // Only web addresses; Bitwarden also keeps app identifiers here.
                let components = URLComponents(string: uri)
                guard ["http", "https", nil].contains(components?.scheme?.lowercased()) else { continue }
                if let site = Website.normalized(components?.host ?? uri), !websites.contains(site), websites.count < Website.maximumPerAccount {
                    websites.append(site)
                }
            }
            if !websites.isEmpty {
                result.details.append(AccountDetails(id: account.id, websites: websites))
            }
        }
        return result
    }

    /// The kind an export names, or nil when it is not one this app supports or
    /// its counter is not a whole number from zero up.
    private static func kind(_ type: String, counter: Any?) -> OTPKind? {
        switch type.lowercased() {
        case "totp": return .totp
        case "steam": return .steam
        case "hotp":
            if counter == nil { return .hotp(counter: 0) }
            // JSON numbers arrive as NSNumber; reading them through their text keeps
            // a negative or fractional value from turning into a different counter.
            guard let number = counter as? NSNumber, let value = UInt64(number.stringValue) else { return nil }
            return .hotp(counter: value)
        default: return nil
        }
    }

    private static func entryLabel(_ issuer: String, _ accountName: String) -> String {
        [issuer, accountName].filter { !$0.isEmpty }.joined(separator: " – ")
    }

    private static func addEntry(
        to result: inout ImportedAccounts,
        issuer: String,
        accountName: String,
        kind: OTPKind?,
        typeName: String,
        secret: String?,
        algorithm: String?,
        digits: Int?,
        period: Int?
    ) {
        let label = entryLabel(issuer, accountName)
        guard let kind else {
            let reason = typeName.uppercased() == "HOTP"
                ? String(localized: "The counter is not valid.")
                : String(localized: "“\(typeName)” codes are not supported.")
            result.skip(label, reason: reason)
            return
        }
        guard let secret, let key = Base32.decode(secret), !key.isEmpty else {
            result.skip(label, reason: String(localized: "The secret key is not valid Base32."))
            return
        }
        guard let parsedAlgorithm = OTPAlgorithm(rawValue: (algorithm ?? "SHA1").uppercased()) else {
            result.skip(label, reason: String(localized: "The algorithm “\(algorithm ?? "")” is not supported."))
            return
        }
        let account = OTPAccount(
            issuer: issuer,
            accountName: accountName,
            secret: key,
            algorithm: parsedAlgorithm,
            digits: digits ?? 6,
            period: period ?? 30,
            kind: kind
        )
        result.add(account, label: label)
    }

    /// A readable name for a key URI that could not be used, without its secret.
    private static func label(of uri: String) -> String {
        guard let components = URLComponents(string: uri) else { return String(localized: "Unnamed") }
        let path = components.path.hasPrefix("/") ? String(components.path.dropFirst()) : components.path
        return path.isEmpty ? String(localized: "Unnamed") : path
    }
}

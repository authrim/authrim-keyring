import Foundation

/// Reads accounts exported by other authenticator apps: a list of `otpauth://`
/// key URIs, or an unencrypted Aegis or 2FAS file.
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
                isTOTP: type == "totp",
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
                isTOTP: type == "TOTP",
                typeName: type,
                secret: service["secret"] as? String,
                algorithm: otp["algorithm"] as? String,
                digits: otp["digits"] as? Int,
                period: otp["period"] as? Int
            )
        }
        return result
    }

    private static func addEntry(
        to result: inout ImportedAccounts,
        issuer: String,
        accountName: String,
        isTOTP: Bool,
        typeName: String,
        secret: String?,
        algorithm: String?,
        digits: Int?,
        period: Int?
    ) {
        let label = [issuer, accountName].filter { !$0.isEmpty }.joined(separator: " – ")
        guard isTOTP else {
            result.skip(label, reason: String(localized: "“\(typeName)” codes are not supported. Only time-based (TOTP) codes can be added."))
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
            period: period ?? 30
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

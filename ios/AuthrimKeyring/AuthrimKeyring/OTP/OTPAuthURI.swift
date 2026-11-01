import Foundation

/// Parser for `otpauth://totp/...` key URIs as produced by setup QR codes.
enum OTPAuthURI {
    enum ParseError: LocalizedError, Equatable {
        case notOTPAuth
        case unsupportedType(String)
        case missingSecret
        case invalidSecret
        case unsupportedAlgorithm(String)
        case unsupportedDigits(String)
        case unsupportedPeriod(String)

        var errorDescription: String? {
            switch self {
            case .notOTPAuth:
                String(localized: "This QR code is not a two-factor authentication setup code.")
            case .unsupportedType(let type):
                String(localized: "“\(type)” codes are not supported. Only time-based (TOTP) codes can be added.")
            case .missingSecret:
                String(localized: "The setup code does not contain a secret key.")
            case .invalidSecret:
                String(localized: "The secret key is not valid Base32.")
            case .unsupportedAlgorithm(let value):
                String(localized: "The algorithm “\(value)” is not supported.")
            case .unsupportedDigits(let value):
                String(localized: "\(value)-digit codes are not supported.")
            case .unsupportedPeriod(let value):
                String(localized: "A period of \(value) seconds is not supported.")
            }
        }
    }

    static func parse(_ text: String) throws(ParseError) -> OTPAccount {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: trimmed),
              components.scheme?.lowercased() == "otpauth",
              let type = components.host?.lowercased()
        else { throw .notOTPAuth }
        guard type == "totp" else { throw .unsupportedType(type.uppercased()) }

        var query: [String: String] = [:]
        for item in components.queryItems ?? [] {
            query[item.name.lowercased()] = item.value ?? ""
        }

        guard let secretText = query["secret"], !secretText.isEmpty else { throw .missingSecret }
        guard let secret = Base32.decode(secretText), !secret.isEmpty else { throw .invalidSecret }

        var algorithm = OTPAlgorithm.sha1
        if let value = query["algorithm"], !value.isEmpty {
            guard let parsed = OTPAlgorithm(rawValue: value.uppercased()) else { throw .unsupportedAlgorithm(value) }
            algorithm = parsed
        }

        var digits = 6
        if let value = query["digits"], !value.isEmpty {
            guard let parsed = Int(value), OTPAccount.supportedDigits.contains(parsed) else { throw .unsupportedDigits(value) }
            digits = parsed
        }

        var period = 30
        if let value = query["period"], !value.isEmpty {
            guard let parsed = Int(value), OTPAccount.supportedPeriods.contains(parsed) else { throw .unsupportedPeriod(value) }
            period = parsed
        }

        // Label is "Issuer:account" or "account"; the path is already percent-decoded.
        var label = components.path
        if label.hasPrefix("/") { label.removeFirst() }
        var labelIssuer = ""
        var accountName = label
        if let colon = label.firstIndex(of: ":") {
            labelIssuer = String(label[..<colon]).trimmingCharacters(in: .whitespaces)
            accountName = String(label[label.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
        }
        // The issuer parameter is authoritative when present.
        let issuer = query["issuer"].flatMap { $0.isEmpty ? nil : $0 } ?? labelIssuer

        return OTPAccount(
            issuer: issuer,
            accountName: accountName,
            secret: secret,
            algorithm: algorithm,
            digits: digits,
            period: period
        )
    }
}

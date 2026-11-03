import Foundation

/// The QR code a computer shows to sign in with a passkey from a phone (FIDO
/// hybrid transport, CTAP 2.2). iOS runs the Bluetooth and relay steps itself
/// and then offers the passkeys of the providers that are turned on, Keyring's included.
enum HybridSignInLink {
    static let scheme = "FIDO"

    /// The link to hand to iOS, if the scanned text is one: "FIDO:/" and the
    /// digits that encode the request (the scheme is case-insensitive).
    static func url(from text: String) -> URL? {
        let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let prefix = scheme + ":/"
        guard text.uppercased().hasPrefix(prefix) else { return nil }
        let digits = text.dropFirst(prefix.count)
        guard !digits.isEmpty, digits.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
        return URL(string: prefix + digits)
    }
}

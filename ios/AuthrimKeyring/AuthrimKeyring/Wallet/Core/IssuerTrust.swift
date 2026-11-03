import Foundation

/// How far Keyring can vouch for who runs an issuer, strongest first. Every level already means the
/// credential's signature was checked against keys the issuer's own https address publishes; the
/// levels differ in who says the organization behind that address is the one it claims to be.
enum IssuerTrust: Equatable, Sendable {
    /// A trust anchor Keyring relies on vouches for the issuer under `name`.
    case verified(name: String, anchor: String)
    /// The user compared a confirmation code with the issuer's admin console, first on this date.
    case confirmedByUser(Date)
    /// Only the address is known. The name is the issuer's own claim.
    case unconfirmed

    /// The level of `issuer`: an anchor's word first, then the user's own earliest confirmation.
    static func of(_ issuer: URL, trusted: [TrustedIssuer], credentials: [StoredCredential]) -> IssuerTrust {
        if let entry = trusted.first(where: { $0.issuer == issuer }) {
            return .verified(name: entry.name, anchor: entry.anchor)
        }
        let confirmations = credentials.filter { $0.issuer == issuer }.compactMap(\.confirmedAt)
        if let first = confirmations.min() { return .confirmedByUser(first) }
        return .unconfirmed
    }
}

/// An issuer a trust anchor vouches for.
struct TrustedIssuer: Equatable, Sendable {
    /// The Credential Issuer identifier, compared exactly.
    let issuer: URL
    /// The organization's name as the anchor states it.
    let name: String
    /// Who vouches, as shown to the user.
    let anchor: String

    /// Empty until Keyring relies on a trust anchor (a signed list, OpenID Federation or X.509 roots).
    static let all: [TrustedIssuer] = []
}

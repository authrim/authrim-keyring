import CryptoKit
import Foundation
import Security

/// Everything that differs between distributors of a Keyring build (the HAIP wallet provider, the
/// pinned roots, the client id, the app-link redirect). A self-hoster edits build settings only:
/// each value is an Info.plist key that an xcconfig fills in. The values compiled in by default are
/// the Authrim project's; they are defaults, never a requirement.
nonisolated struct WalletDeploymentConfig: Sendable, Equatable {
    enum ProviderKind: String, Sendable, Equatable {
        /// Verifies Apple App Attest. The only kind a release build accepts.
        case appAttest
        /// No platform attestation. Compiled into debug builds only.
        case debugUnattested
    }

    enum Problem: Error, Equatable {
        case missing(String)
        case invalid(String)
    }

    let providerKind: ProviderKind
    /// https origin of the wallet provider; nil until a deployment configures one.
    let providerOrigin: URL?
    /// `iss` of the provider's attestations (defaults to the origin).
    let providerIssuer: URL?
    /// DER of the provider roots wallet and key attestations must chain to (several, for rotation).
    let providerRoots: [Data]
    /// Credential issuer identifiers (exact https origins) the provider attests for.
    let credentialIssuers: Set<String>
    /// Hosts besides the verifier's own that the sign-in may return the browser to (a separate console host).
    let consoleHosts: Set<String>
    /// The attestation `sub` and the OP allowlist `clientId`.
    let clientID: String
    /// The https app-link callback of the authorization code flow.
    let redirectURI: URL
    /// DER of the roots the issuer's `x5c` chain (and the verifier's request chain) must end at.
    let authrimRoots: [Data]

    static let defaultClientID = "keyring-ios"

    /// Keys of the app's Info.plist.
    enum Key {
        static let providerKind = "WalletProviderKind"
        static let providerOrigin = "WalletProviderOrigin"
        static let providerIssuer = "WalletProviderIssuer"
        static let providerRoots = "WalletProviderPinnedRoots"
        static let issuers = "WalletProviderIssuers"
        static let consoleHosts = "AuthrimConsoleHosts"
        static let clientID = "WalletClientID"
        static let redirectURI = "WalletRedirectURI"
        static let authrimRoots = "AuthrimTrustedRoots"
    }

    /// Reads the configuration. Roots are lists of base64 DER certificates; a malformed value
    /// fails the whole configuration rather than being skipped.
    init(info: [String: Any], allowDebugProvider: Bool) throws {
        func text(_ key: String) -> String? {
            (info[key] as? String).flatMap { $0.isEmpty || $0.hasPrefix("$(") ? nil : $0 }
        }
        func url(_ key: String) throws -> URL? {
            guard let value = text(key) else { return nil }
            guard let parsed = URL(string: value), (try? WalletHTTP.requireHTTPS(parsed, key)) != nil else {
                throw Problem.invalid(key)
            }
            return parsed
        }
        func roots(_ key: String) throws -> [Data] {
            guard let raw = info[key] else { return [] }
            guard let list = raw as? [String], list.count <= 8 else { throw Problem.invalid(key) }
            return try list.filter { !$0.isEmpty && !$0.hasPrefix("$(") }.map { entry in
                guard let der = Data(base64Encoded: entry), SecCertificateCreateWithData(nil, der as CFData) != nil
                else { throw Problem.invalid(key) }
                return der
            }
        }
        let kindText = text(Key.providerKind) ?? ProviderKind.appAttest.rawValue
        guard let kind = ProviderKind(rawValue: kindText) else { throw Problem.invalid(Key.providerKind) }
        guard kind == .appAttest || allowDebugProvider else { throw Problem.invalid(Key.providerKind) }
        providerKind = kind
        providerOrigin = try url(Key.providerOrigin)
        providerIssuer = try url(Key.providerIssuer) ?? providerOrigin
        providerRoots = try roots(Key.providerRoots)
        authrimRoots = try roots(Key.authrimRoots)
        var issuers = Set<String>()
        if let raw = info[Key.issuers] {
            guard let list = raw as? [String], list.count <= 16 else { throw Problem.invalid(Key.issuers) }
            for entry in list where !entry.isEmpty && !entry.hasPrefix("$(") {
                guard let parsed = URL(string: entry), (try? WalletHTTP.requireHTTPS(parsed, Key.issuers)) != nil,
                      parsed.absoluteString == entry, !entry.hasSuffix("/"), parsed.query == nil, parsed.fragment == nil
                else { throw Problem.invalid(Key.issuers) }
                issuers.insert(entry)
            }
        }
        credentialIssuers = issuers
        var hosts = Set<String>()
        if let raw = info[Key.consoleHosts] {
            guard let list = raw as? [String], list.count <= 8 else { throw Problem.invalid(Key.consoleHosts) }
            for entry in list where !entry.isEmpty && !entry.hasPrefix("$(") {
                guard entry.wholeMatch(of: /[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?/) != nil, entry.contains(".")
                else { throw Problem.invalid(Key.consoleHosts) }
                hosts.insert(entry)
            }
        }
        consoleHosts = hosts
        let client = text(Key.clientID) ?? Self.defaultClientID
        guard client.wholeMatch(of: /[A-Za-z0-9_-]{1,128}/) != nil else { throw Problem.invalid(Key.clientID) }
        clientID = client
        guard let redirect = try url(Key.redirectURI), AuthorizationCodeFlow.isValidRedirect(redirect) else {
            throw Problem.missing(Key.redirectURI)
        }
        redirectURI = redirect
    }

    /// The configuration of the running app.
    static func current(bundle: Bundle = .main) throws -> WalletDeploymentConfig {
        #if DEBUG
        let allowDebug = true
        #else
        let allowDebug = false
        #endif
        return try WalletDeploymentConfig(info: bundle.infoDictionary ?? [:], allowDebugProvider: allowDebug)
    }

    /// Whether HAIP issuance may start. A release build with no provider origin or no pinned
    /// provider root fails closed: it never falls back to unattested requests.
    func requireHAIPReady(isRelease: Bool) throws {
        guard providerOrigin != nil else { throw Problem.missing(Key.providerOrigin) }
        guard !providerRoots.isEmpty else { throw Problem.missing(Key.providerRoots) }
        if isRelease && providerKind != .appAttest { throw Problem.invalid(Key.providerKind) }
        guard !authrimRoots.isEmpty else { throw Problem.missing(Key.authrimRoots) }
        guard !credentialIssuers.isEmpty else { throw Problem.missing(Key.issuers) }
    }
}

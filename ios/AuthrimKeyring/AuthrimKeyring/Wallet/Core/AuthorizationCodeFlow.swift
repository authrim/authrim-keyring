import AuthenticationServices
import CryptoKit
import Foundation
import Security
import UIKit

/// The authorization response is delivered only to the authentication session that opened the page.
nonisolated protocol AuthorizationBrowser: Sendable {
    @MainActor func authorize(_ url: URL, redirectURI: URL) async throws -> URL
}

@MainActor
final class SystemAuthorizationBrowser: NSObject, AuthorizationBrowser, ASWebAuthenticationPresentationContextProviding {
    private var activeSession: ASWebAuthenticationSession?
    private var continuation: CheckedContinuation<URL, Error>?
    private var anchor: ASPresentationAnchor?

    func authorize(_ url: URL, redirectURI: URL) async throws -> URL {
        guard activeSession == nil else {
            throw WalletError.invalidIssuer("An authorization page is already open.")
        }
        guard let window = UIApplication.shared.connectedScenes
            .compactMap({ $0 as? UIWindowScene })
            .flatMap(\.windows)
            .first(where: \.isKeyWindow) else {
            throw WalletError.network("The authorization page needs an active app window.")
        }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                if Task.isCancelled {
                    continuation.resume(throwing: WalletError.authorizationDenied)
                    return
                }
                let handler: (URL?, Error?) -> Void = { [weak self] callback, error in
                    Task { @MainActor in
                        if let callback {
                            self?.finish(.success(callback))
                        } else if let error = error as NSError?,
                                  error.domain == ASWebAuthenticationSessionErrorDomain,
                                  error.code == ASWebAuthenticationSessionError.Code.canceledLogin.rawValue {
                            self?.finish(.failure(WalletError.authorizationDenied))
                        } else {
                            self?.finish(.failure(WalletError.network(
                                error?.localizedDescription ?? "The authorization page was closed.")))
                        }
                    }
                }
                let session: ASWebAuthenticationSession
                do { session = try Self.makeSession(url: url, redirectURI: redirectURI, handler: handler) } catch {
                    continuation.resume(throwing: error)
                    return
                }
                session.presentationContextProvider = self
                self.continuation = continuation
                activeSession = session
                anchor = window
                if !session.start() {
                    finish(.failure(WalletError.network("The authorization page could not be opened.")))
                }
            }
        } onCancel: {
            Task { @MainActor [weak self] in
                self?.activeSession?.cancel()
                self?.finish(.failure(WalletError.authorizationDenied))
            }
        }
    }

    /// A custom-scheme redirect uses the scheme; an https redirect (an app link) needs the https
    /// callback form, available from iOS 17.4.
    private static func makeSession(
        url: URL, redirectURI: URL, handler: @escaping (URL?, Error?) -> Void
    ) throws -> ASWebAuthenticationSession {
        if redirectURI.scheme?.lowercased() == "https" {
            guard #available(iOS 17.4, *), let host = redirectURI.host else {
                throw WalletError.invalidIssuer("An https redirect needs iOS 17.4 or later.")
            }
            return ASWebAuthenticationSession(
                url: url, callback: .https(host: host, path: redirectURI.path), completionHandler: handler)
        }
        guard let scheme = redirectURI.scheme else {
            throw WalletError.invalidIssuer("The redirect URI has no scheme.")
        }
        return ASWebAuthenticationSession(url: url, callbackURLScheme: scheme, completionHandler: handler)
    }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        anchor ?? UIWindow()
    }

    private func finish(_ result: Result<URL, Error>) {
        guard let continuation else { return }
        self.continuation = nil
        activeSession = nil
        anchor = nil
        continuation.resume(with: result)
    }
}

/// The registered redirect URI is deliberately different from the credential-offer schemes.
nonisolated enum AuthorizationCodeFlow {
    /// The built-in redirect (custom scheme). A HAIP deployment configures an https app link instead
    /// (`WalletDeploymentConfig.redirectURI`); the OP accepts only https redirect URIs for wallets.
    static let redirectURI = URL(string: "com.authrim.keyring://oauth/callback")!

    /// A redirect URI the wallet can receive: a custom scheme or https, with a host and path, no
    /// credentials, port, query or fragment.
    static func isValidRedirect(_ uri: URL) -> Bool {
        guard let components = URLComponents(url: uri, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(), let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil, components.port == nil,
              components.query == nil, components.fragment == nil, components.path.count > 1
        else { return false }
        return scheme == "https" || scheme.contains(".")
    }

    static func randomURLSafeValue() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw WalletError.keyUnavailable("Secure OAuth randomness is unavailable.")
        }
        return Base64URL.encode(Data(bytes))
    }

    static func challenge(for verifier: String) -> String {
        Base64URL.encode(Data(SHA256.hash(data: Data(verifier.utf8))))
    }

    static func authorizationURL(endpoint: URL, clientID: String, requestURI: String) throws -> URL {
        guard requestURI.utf8.count <= 2048, !requestURI.isEmpty,
              requestURI.utf8.allSatisfy({ (0x21...0x7e).contains($0) }),
              var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false),
              components.fragment == nil else {
            throw WalletError.invalidIssuer("The pushed authorization response is invalid.")
        }
        let existingItems = components.queryItems ?? []
        guard !existingItems.contains(where: { $0.name == "client_id" || $0.name == "request_uri" }) else {
            throw WalletError.invalidIssuer("The authorization endpoint duplicates a request parameter.")
        }
        components.queryItems = existingItems + [
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "request_uri", value: requestURI),
        ]
        guard let url = components.url else {
            throw WalletError.invalidIssuer("The authorization URL could not be built.")
        }
        return url
    }

    static func code(
        from callback: URL, state: String, authorizationServer: URL, redirectURI: URL = redirectURI
    ) throws -> String {
        guard let components = URLComponents(url: callback, resolvingAgainstBaseURL: false),
              components.scheme?.lowercased() == redirectURI.scheme,
              components.host?.lowercased() == redirectURI.host,
              components.percentEncodedPath == URLComponents(
                  url: redirectURI, resolvingAgainstBaseURL: false)?.percentEncodedPath,
              components.user == nil, components.password == nil, components.port == nil,
              components.fragment == nil else {
            throw WalletError.invalidIssuer("The authorization callback does not match Keyring's redirect URI.")
        }
        let items = components.queryItems ?? []
        func one(_ name: String) -> String? {
            let matches = items.filter { $0.name == name }
            return matches.count == 1 ? matches[0].value : nil
        }
        guard let returnedState = one("state"), constantTimeEqual(returnedState, state),
              one("iss") == authorizationServer.absoluteString else {
            throw WalletError.invalidIssuer("The authorization response has the wrong state or issuer.")
        }
        if items.contains(where: { $0.name == "error" }) {
            guard one("error") != nil else {
                throw WalletError.invalidIssuer("The authorization response is malformed.")
            }
            throw WalletError.authorizationDenied
        }
        guard let code = one("code"), !code.isEmpty, code.utf8.count <= 8 * 1024,
              code.utf8.allSatisfy({ (0x20...0x7e).contains($0) }) else {
            throw WalletError.invalidIssuer("The authorization response has no valid code.")
        }
        return code
    }

    private static func constantTimeEqual(_ left: String, _ right: String) -> Bool {
        let lhs = Array(left.utf8), rhs = Array(right.utf8)
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for index in lhs.indices { difference |= lhs[index] ^ rhs[index] }
        return difference == 0
    }
}

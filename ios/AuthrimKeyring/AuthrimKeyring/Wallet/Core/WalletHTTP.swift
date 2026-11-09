import Foundation
import Network
import Security

nonisolated struct WalletHTTPResponse: Sendable {
    let status: Int
    let data: Data
    /// RFC 9449 challenge for the next DPoP proof, if supplied by this server.
    let dpopNonce: String?
    let wwwAuthenticate: String?
    let clientAttestationChallenge: String?

    var isSuccess: Bool { (200..<300).contains(status) }

    /// The OAuth / OpenID4VCI `error` code of a JSON error body, if there is one.
    var errorCode: String? {
        guard let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return nil }
        return object["error"] as? String
    }
}

/// The wallet's only network path. Every request is https, never follows a redirect, has a
/// 15 s timeout and a response size cap, and uses an ephemeral session (no cookies, no cache,
/// no stored credentials). Production sessions connect through WalletPublicProxy, which verifies
/// the actual destination before allowing URLSession to send HTTP or TLS bytes. Callers select
/// sensitive request URLs from identity-checked metadata; `origin:` can restrict one origin.
nonisolated final class WalletHTTP: Sendable {
    static let jsonLimit = 64 * 1024
    /// Issuer metadata can list many credential configurations; keep its larger allowance bounded.
    static let issuerMetadataLimit = 256 * 1024
    /// SD-JWT VCs can carry an issuer-provided portrait as a data URL. Keep the response bounded
    /// while allowing a normal JPEG credential to pass after its one-time code was redeemed.
    static let credentialLimit = 1024 * 1024
    static let timeout: TimeInterval = 15

    private let injectedSession: URLSession?
    private let publicProxy: WalletPublicProxy?

    /// `protocolClasses` lets tests stub the network with a `URLProtocol`.
    init(protocolClasses: [AnyClass]? = nil, publicAddressResolver: WalletPublicProxy.Resolver? = nil) {
        if let protocolClasses {
            let configuration = Self.configuration()
            configuration.protocolClasses = protocolClasses
            injectedSession = URLSession(
                configuration: configuration, delegate: NoRedirectDelegate(), delegateQueue: nil)
            publicProxy = nil
        } else {
            injectedSession = nil
            publicProxy = WalletPublicProxy(resolve: publicAddressResolver ?? { try WalletPublicProxy.systemAddresses($0) })
        }
    }

    private static func configuration() -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.urlCache = nil
        configuration.urlCredentialStorage = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.timeoutIntervalForRequest = Self.timeout
        configuration.timeoutIntervalForResource = Self.timeout
        configuration.waitsForConnectivity = false
        configuration.tlsMinimumSupportedProtocolVersion = .TLSv12
        return configuration
    }

    deinit {
        injectedSession?.invalidateAndCancel()
        publicProxy?.stop()
    }

    // MARK: URL rules

    /// https, a public host, no user info; returns the validated URL. Offers arrive from links and QR
    /// codes, so a hostile offer must not make the phone call into its local network.
    static func requireHTTPS(_ url: URL, _ what: String) throws -> URL {
        guard url.scheme?.lowercased() == "https", let host = url.host, !host.isEmpty,
              url.user == nil, url.password == nil
        else { throw WalletError.network("\(what) must be an https URL.") }
        guard isPublicHost(host) else { throw WalletError.network("\(what) must be a public host.") }
        return url
    }

    /// False for local names and for loopback, private, link-local, CGNAT, unique-local and
    /// unspecified IP literals (IPv4-mapped IPv6 included). The production transport also
    /// checks DNS answers and the connected peer's numeric address before sending any HTTP bytes.
    static func isPublicHost(_ host: String) -> Bool {
        let name = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]."))
        if name == "localhost" || [".localhost", ".local", ".internal", ".home.arpa"].contains(where: name.hasSuffix) {
            return false
        }
        if let v4 = ipv4(name) { return isPublicIPv4(v4) }
        guard name.contains(":") else { return true }
        var address = in6_addr()
        guard inet_pton(AF_INET6, name, &address) == 1 else { return false }
        let bytes = withUnsafeBytes(of: &address) { Array($0) }
        // IPv4-mapped (::ffff:0:0/96) and IPv4-compatible (::/96, which also holds :: and ::1).
        if bytes[0..<10].allSatisfy({ $0 == 0 }),
           (bytes[10] == 0xff && bytes[11] == 0xff) || (bytes[10] == 0 && bytes[11] == 0) {
            return isPublicIPv4(Array(bytes[12..<16]))
        }
        if bytes[0..<4] == [0x00, 0x64, 0xff, 0x9b] {
            // The well-known NAT64 /96 can translate a public IPv4 address on IPv6-only
            // networks. Other subprefixes include the local-use 64:ff9b:1::/48.
            return bytes[4..<12].allSatisfy({ $0 == 0 }) && isPublicIPv4(Array(bytes[12..<16]))
        }
        if bytes[0..<2] == [0x20, 0x01], bytes[2] & 0xfe == 0 {
            // 2001::/23 is not globally reachable except for these specific IANA allocations.
            // This also rejects Teredo, benchmarking, deprecated and unallocated addresses.
            if bytes[2] == 0 {
                if bytes[3] == 0x01, bytes[4..<15].allSatisfy({ $0 == 0 }),
                   (1...3).contains(bytes[15]) { return true }  // 2001:1::1–3/128
                if bytes[3] == 0x03 { return true }  // 2001:3::/32 AMT
                if bytes[3] == 0x04, bytes[4] == 0x01, bytes[5] == 0x12 { return true }  // AS112-v6 /48
                if bytes[3] & 0xf0 == 0x20 || bytes[3] & 0xf0 == 0x30 { return true }  // ORCHIDv2 and DETs /28
            }
            return false
        }
        if bytes[0..<2] == [0x20, 0x02] { return false }  // 2002::/16 6to4
        if bytes[0] & 0xfe == 0xfc { return false }  // fc00::/7
        if bytes[0] == 0xfe, bytes[1] & 0xc0 == 0x80 { return false }  // fe80::/10
        if bytes[0] == 0xfe, bytes[1] & 0xc0 == 0xc0 { return false }  // fec0::/10 site-local
        if bytes[0] == 0xff { return false }  // multicast
        if bytes[0] & 0xe0 != 0x20 { return false }  // only 2000::/3 global unicast
        if bytes[0..<4] == [0x20, 0x01, 0x0d, 0xb8] { return false }  // documentation
        if bytes[0] == 0x3f, bytes[1] == 0xff, bytes[2] & 0xf0 == 0 { return false }  // 3fff::/20 documentation
        return true
    }

    private static func ipv4(_ name: String) -> [UInt8]? {
        // inet_aton also takes the short and numeric forms ("127.1", "2130706433") resolvers accept.
        var address = in_addr()
        guard inet_aton(name, &address) == 1 else { return nil }
        return withUnsafeBytes(of: &address) { Array($0) }
    }

    private static func isPublicIPv4(_ b: [UInt8]) -> Bool {
        switch (b[0], b[1]) {
        case (0, _), (10, _), (127, _): return false
        case (100, 64...127): return false
        case (169, 254), (192, 168): return false
        case (192, 0) where b[2] == 0: return false  // 192.0.0.0/24
        case (192, 0) where b[2] == 2: return false  // 192.0.2.0/24 documentation
        case (192, 88) where b[2] == 99: return false  // deprecated 6to4 relay
        case (172, 16...31), (198, 18...19): return false
        case (198, 51) where b[2] == 100: return false  // documentation
        case (203, 0) where b[2] == 113: return false  // documentation
        case (224...255, _): return false  // multicast, reserved, broadcast
        default: return true
        }
    }

    /// Scheme, host (case-insensitive) and effective port all match.
    static func sameOrigin(_ a: URL, _ b: URL) -> Bool {
        guard let schemeA = a.scheme?.lowercased(), let schemeB = b.scheme?.lowercased(),
              let hostA = a.host?.lowercased(), let hostB = b.host?.lowercased() else { return false }
        return schemeA == schemeB && hostA == hostB && (a.port ?? 443) == (b.port ?? 443)
    }

    // MARK: Requests

    /// Sends a request. Redirects are not followed: a 3xx answer is an error. Other statuses are
    /// returned to the caller, which maps protocol errors (`invalid_grant` ...).
    /// - Parameter origin: when set, the URL must be on this origin or nothing is sent.
    func send(
        _ url: URL, method: String = "GET", headers: [String: String] = [:], body: Data? = nil,
        maxBytes: Int = WalletHTTP.jsonLimit, origin: URL? = nil
    ) async throws -> WalletHTTPResponse {
        _ = try Self.requireHTTPS(url, "The request URL")
        if let origin, !Self.sameOrigin(url, origin) {
            throw WalletError.invalidIssuer("An endpoint is not on the expected origin.")
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.httpBody = body
        request.httpShouldHandleCookies = false
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.timeoutInterval = Self.timeout
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        for (name, value) in headers { request.setValue(value, forHTTPHeaderField: name) }

        let session: URLSession
        let ownsSession: Bool
        if let injectedSession {
            session = injectedSession
            ownsSession = false
        } else {
            guard let publicProxy else { throw WalletError.network("The wallet network path is unavailable.") }
            let port = try await publicProxy.begin(url)
            let configuration = Self.configuration()
            var proxy = ProxyConfiguration(
                httpCONNECTProxy: .hostPort(host: .ipv4(.loopback), port: port))
            proxy.allowFailover = false
            configuration.proxyConfigurations = [proxy]
            session = URLSession(configuration: configuration, delegate: NoRedirectDelegate(), delegateQueue: nil)
            ownsSession = true
        }
        defer {
            if ownsSession {
                session.invalidateAndCancel()
                publicProxy?.end(url)
            }
        }

        do {
            let (bytes, response) = try await session.bytes(for: request)
            guard let http = response as? HTTPURLResponse else { throw WalletError.network("No HTTP response.") }
            if (300..<400).contains(http.statusCode) { throw WalletError.network("Redirects are not followed.") }
            if response.expectedContentLength > Int64(maxBytes) { throw WalletError.outcomeUnknown("The response is too large.") }
            var data = Data()
            for try await byte in bytes {
                data.append(byte)
                if data.count > maxBytes { throw WalletError.outcomeUnknown("The response is too large.") }
            }
            return WalletHTTPResponse(
                status: http.statusCode, data: data,
                dpopNonce: http.value(forHTTPHeaderField: "DPoP-Nonce"),
                wwwAuthenticate: http.value(forHTTPHeaderField: "WWW-Authenticate"),
                clientAttestationChallenge: http.value(forHTTPHeaderField: "OAuth-Client-Attestation-Challenge"))
        } catch let error as WalletError {
            throw error
        } catch let error as URLError where error.code == .cancelled {
            throw CancellationError()
        } catch let error as URLError {
            // Only failures that certainly happened before the request left the device are plain
            // network errors; anything later leaves the outcome unknown (the server may have acted).
            if Self.failedBeforeSending(error) { throw WalletError.network(error.localizedDescription) }
            throw WalletError.outcomeUnknown(error.localizedDescription)
        }
    }

    /// GET that must answer 200 with a JSON object.
    func getJSON(_ url: URL, origin: URL? = nil, maxBytes: Int = WalletHTTP.jsonLimit) async throws -> [String: Any] {
        let response = try await send(url, maxBytes: maxBytes, origin: origin)
        guard response.status == 200 else { throw WalletError.network("HTTP \(response.status) from \(url.host ?? "server").") }
        guard let object = (try? JSONSerialization.jsonObject(with: response.data)) as? [String: Any] else {
            throw WalletError.invalidIssuer("A response is not a JSON object.")
        }
        return object
    }

    /// Form body for the token request (RFC 6749 appendix B, application/x-www-form-urlencoded).
    static func formBody(_ fields: [(String, String)]) -> Data {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        func escape(_ value: String) -> String { value.addingPercentEncoding(withAllowedCharacters: allowed) ?? "" }
        return Data(fields.map { "\(escape($0.0))=\(escape($0.1))" }.joined(separator: "&").utf8)
    }

    /// URL loading errors that occur before any request bytes reach the server.
    private static func failedBeforeSending(_ error: URLError) -> Bool {
        switch error.code {
        case .notConnectedToInternet, .cannotFindHost, .dnsLookupFailed, .cannotConnectToHost,
             .secureConnectionFailed, .serverCertificateUntrusted, .serverCertificateHasBadDate,
             .serverCertificateNotYetValid, .serverCertificateHasUnknownRoot, .clientCertificateRejected,
             .clientCertificateRequired, .appTransportSecurityRequiresSecureConnection, .badURL,
             .unsupportedURL, .internationalRoamingOff, .dataNotAllowed, .callIsActive:
            true
        default:
            false
        }
    }
}

/// Refuses every redirect, so the task completes with the 3xx response itself.
private final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate, Sendable {
    /// Certificate validation can otherwise fetch issuer-supplied AIA/OCSP/CRL URLs outside
    /// WalletPublicProxy. A QR-controlled server must not induce those hidden network requests.
    func urlSession(
        _ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust,
              SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
              SecTrustEvaluateWithError(trust, nil) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }

    func urlSession(
        _ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

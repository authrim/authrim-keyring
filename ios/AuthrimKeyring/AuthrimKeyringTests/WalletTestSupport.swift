import CryptoKit
import Foundation
import Testing
@testable import AuthrimKeyring

/// The suites that share `StubURLProtocol`'s registry: nested here so they never run in parallel
/// with each other (`.serialized` applies to every suite inside).
@Suite(.serialized) enum StubbedNetworkTests {}

/// Routes every request of a `WalletHTTP` to a handler keyed by "METHOD url".
final class StubURLProtocol: URLProtocol, @unchecked Sendable {
    struct Reply {
        var status = 200
        var headers: [String: String] = [:]
        var body = Data()
        var redirectTo: URL?
        /// Fail the request with this URL loading error instead of answering.
        var failWith: URLError.Code?
    }

    nonisolated(unsafe) static var handlers: [String: (URLRequest) -> Reply] = [:]
    nonisolated(unsafe) static var seen: [URLRequest] = []
    nonisolated(unsafe) static var bodies: [String: Data] = [:]
    private static let lock = NSLock()

    static func reset() {
        lock.lock(); defer { lock.unlock() }
        handlers = [:]; seen = []; bodies = [:]
    }

    static func on(_ method: String, _ url: String, json: Any, status: Int = 200) {
        let data = (try? JSONSerialization.data(withJSONObject: json)) ?? Data()
        lock.lock(); defer { lock.unlock() }
        handlers["\(method) \(url)"] = { _ in Reply(status: status, headers: ["Content-Type": "application/json"], body: data) }
    }

    static func on(_ method: String, _ url: String, _ handler: @escaping (URLRequest) -> Reply) {
        lock.lock(); defer { lock.unlock() }
        handlers["\(method) \(url)"] = handler
    }

    static func requests(to url: String) -> [URLRequest] {
        lock.lock(); defer { lock.unlock() }
        return seen.filter { $0.url?.absoluteString == url }
    }

    static func body(of url: String) -> Data? {
        lock.lock(); defer { lock.unlock() }
        return bodies[url]
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let key = "\(request.httpMethod ?? "GET") \(request.url?.absoluteString ?? "")"
        var captured = request.httpBody
        if captured == nil, let stream = request.httpBodyStream {
            stream.open(); defer { stream.close() }
            var data = Data()
            var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let count = stream.read(&buffer, maxLength: buffer.count)
                if count <= 0 { break }
                data.append(buffer, count: count)
            }
            captured = data
        }
        Self.lock.lock()
        Self.seen.append(request)
        if let url = request.url?.absoluteString, let captured { Self.bodies[url] = captured }
        let handler = Self.handlers[key]
        Self.lock.unlock()

        guard let handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.resourceUnavailable))
            return
        }
        let reply = handler(request)
        if let code = reply.failWith {
            client?.urlProtocol(self, didFailWithError: URLError(code))
            return
        }
        if let target = reply.redirectTo {
            let response = HTTPURLResponse(url: request.url!, statusCode: 302, httpVersion: nil, headerFields: ["Location": target.absoluteString])!
            client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: target), redirectResponse: response)
            return
        }
        let response = HTTPURLResponse(url: request.url!, statusCode: reply.status, httpVersion: nil, headerFields: reply.headers)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: reply.body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

/// A holder key held in memory, standing in for the Secure Enclave.
struct TestSigner: HolderSigning {
    let tag: String
    let key: P256.Signing.PrivateKey
    var publicJWK: PublicJWK { PublicJWK(x963: key.publicKey.x963Representation)! }
    func sign(_ message: Data) throws -> Data { try key.signature(for: message).rawRepresentation }
}

final class MemoryStore: CredentialStore, @unchecked Sendable {
    var items: [StoredCredential] = []
    var failSave = false
    func loadAll() throws -> [StoredCredential] { items }
    func save(_ credential: StoredCredential) throws {
        if failSave { throw WalletError.storage("full") }
        items.append(credential)
    }
    func delete(_ credential: StoredCredential) throws { items.removeAll { $0.id == credential.id } }
}

nonisolated final class Box<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: T

    init(_ value: T) { stored = value }

    var value: T {
        get { lock.lock(); defer { lock.unlock() }; return stored }
        set { lock.lock(); defer { lock.unlock() }; stored = newValue }
    }
}

/// Builds the issuer side: metadata documents and SD-JWT VCs signed with a software key.
struct TestIssuer {
    nonisolated static let base = "https://issuer.example.com"
    nonisolated static let vct = "https://issuer.example.com/vct/admin-credential"
    let issuerKey = P256.Signing.PrivateKey()
    let kid = "key-1"

    var issuerJWK: [String: Any] {
        let jwk = PublicJWK(x963: issuerKey.publicKey.x963Representation)!
        return ["kty": "EC", "crv": "P-256", "x": jwk.x, "y": jwk.y, "kid": kid, "use": "sig", "alg": "ES256"]
    }

    static func offerJSON(
        issuer: String = base, ids: [String] = ["admin"], txCode: Bool = true
    ) -> [String: Any] {
        var grant: [String: Any] = ["pre-authorized_code": "PRE-CODE"]
        if txCode { grant["tx_code"] = ["input_mode": "numeric", "length": 6, "description": "Shown in the console"] }
        return ["credential_issuer": issuer, "credential_configuration_ids": ids,
                "grants": [CredentialOfferParser.preAuthorizedGrant: grant]]
    }

    static func issuerMetadata(
        issuer: String = base, credentialEndpoint: String = base + "/vci/credential",
        nonceEndpoint: String = base + "/vci/nonce", servers: [String] = [base + "/vci"],
        format: String = "dc+sd-jwt"
    ) -> [String: Any] {
        [
            "credential_issuer": issuer, "authorization_servers": servers,
            "credential_endpoint": credentialEndpoint, "nonce_endpoint": nonceEndpoint,
            "display": [["name": "Autorim", "locale": "en"], ["name": "オースリム", "locale": "ja"]],
            "credential_configurations_supported": [
                "admin": [
                    "format": format, "scope": "admin", "vct": vct,
                    "cryptographic_binding_methods_supported": ["jwk"],
                    "credential_signing_alg_values_supported": ["ES256"],
                    "proof_types_supported": ["jwt": ["proof_signing_alg_values_supported": ["ES256"]]],
                    "credential_metadata": [
                        "display": [["name": "Admin credential", "locale": "en"], ["name": "管理者資格", "locale": "ja"]],
                        "claims": [
                            ["path": ["email"], "display": [["name": "Email", "locale": "en"], ["name": "メール", "locale": "ja"]]],
                            ["path": ["name"], "display": [["name": "Name", "locale": "en"]]],
                        ],
                    ],
                ] as [String: Any]
            ],
        ]
    }

    static func serverMetadata(issuer: String = base + "/vci", tokenEndpoint: String = base + "/vci/token") -> [String: Any] {
        ["issuer": issuer, "token_endpoint": tokenEndpoint,
         "grant_types_supported": [CredentialOfferParser.preAuthorizedGrant],
         "pre-authorized_grant_anonymous_access_supported": true]
    }

    func jwks(issuer: String = TestIssuer.base) -> [String: Any] { ["issuer": issuer, "jwks": ["keys": [issuerJWK]]] }

    struct Options {
        var iss = TestIssuer.base
        var vct = TestIssuer.vct
        var typ = "dc+sd-jwt"
        var exp: Date = Date().addingTimeInterval(3600)
        var iat: Date = Date()
        var cnf: PublicJWK?
        var tamperDisclosure = false
        var signWith: P256.Signing.PrivateKey?
        var extraHeader: [String: Any] = [:]
        var extraPayload: [String: Any] = [:]
        /// Name of the disclosed claim (default `email`).
        var disclosureName = "email"
        /// Lists the disclosure digest twice in `_sd`.
        var duplicateDigest = false
        /// Also references the disclosure digest as an array element `{"...": digest}`.
        var duplicateDigestInArray = false
    }

    /// An SD-JWT VC with one selectively disclosed claim (`email`) and one plain claim (`sub`).
    func sdJwt(holder: PublicJWK, _ options: Options = Options()) throws -> String {
        let disclosure = Base64URL.encode(Data(#"["salt1","\#(options.disclosureName)","admin@example.com"]"#.utf8))
        let digest = Base64URL.encode(Data(SHA256.hash(data: Data(disclosure.utf8))))
        let bound = options.cnf ?? holder
        var payload: [String: Any] = [
            "iss": options.iss, "vct": options.vct, "iat": Int(options.iat.timeIntervalSince1970),
            "exp": Int(options.exp.timeIntervalSince1970), "sub": "user-1", "_sd_alg": "sha-256", "_sd": options.duplicateDigest ? [digest, digest] : [digest],
            "cnf": ["jwk": bound.proofMembers], "status": ["status_list": ["idx": 1, "uri": "https://issuer.example.com/s"]],
        ]
        if options.duplicateDigestInArray { payload["items"] = [["...": digest]] }
        payload.merge(options.extraPayload) { _, new in new }
        var header: [String: Any] = ["alg": "ES256", "typ": options.typ, "kid": kid]
        header.merge(options.extraHeader) { _, new in new }
        let signer = options.signWith ?? issuerKey
        let jwt = try JWS.make(header: header, payload: payload) { try signer.signature(for: $0).rawRepresentation }
        let shown = options.tamperDisclosure ? Base64URL.encode(Data(#"["salt1","email","evil@example.com"]"#.utf8)) : disclosure
        return jwt + "~" + shown + "~"
    }
}

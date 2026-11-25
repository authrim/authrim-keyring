import CryptoKit
import DeviceCheck
import Foundation

/// The wallet provider client of the contract in `20261124-keyring-wallet-provider-contract.md`.
/// It proves the app instance with App Attest, asks the provider for a wallet attestation (for the
/// session's DPoP key) or a key attestation (for a holder key and the issuer's `c_nonce`), and
/// checks the answer against provider roots pinned in the build before anything is sent on.
nonisolated final class AuthrimWalletProvider: WalletAttestationProvider, KeyAttestationProvider, @unchecked Sendable {
    enum Purpose: String { case wallet = "wallet-attestation", key = "key-attestation" }

    private let origin: URL
    private let issuer: URL
    private let roots: [Data]
    private let clientID: String
    private let issuers: Set<String>
    private let appAttest: any AppAttestService
    private let state: any AppAttestStateStore
    private let http: WalletHTTP
    private let now: @Sendable () -> Date
    private let gate = Gate()

    init(
        origin: URL, issuer: URL, roots: [Data], clientID: String, issuers: Set<String>,
        appAttest: any AppAttestService, state: any AppAttestStateStore,
        http: WalletHTTP = WalletHTTP(), now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.origin = origin
        self.issuer = issuer
        self.roots = roots
        self.clientID = clientID
        self.issuers = issuers
        self.appAttest = appAttest
        self.state = state
        self.http = http
        self.now = now
    }

    /// Only the credential issuers the build lists get an attestation.
    func supports(issuer: URL) -> Bool {
        issuers.contains(issuer.absoluteString) && !roots.isEmpty && appAttest.isSupported
    }

    // MARK: Wallet attestation (for the DPoP key)

    func attestation(for clientKey: PublicJWK, issuer target: URL) async throws -> WalletClientAttestation {
        guard supports(issuer: target) else { throw WalletError.unsupportedKeyAttestation }
        let jwt = try await request(.wallet, key: clientKey, nonce: nil)
        do {
            let result = try WalletAttestationVerifier.validate(
                jwt, clientKey: clientKey, providerIssuer: issuer, trustedRootDER: roots, now: now())
            try Self.checkContract(jwt, now: now())
            // The allowlist names one client id; a provider answering with another is misconfigured.
            guard result.clientID == clientID else {
                throw WalletError.invalidIssuer("The wallet provider named an unexpected client id.")
            }
            return result
        } catch let error as WalletError {
            throw error
        } catch {
            throw WalletError.invalidIssuer("The wallet attestation did not validate.")
        }
    }

    // MARK: Key attestation (for a holder key)

    func attestation(for holderKey: PublicJWK, nonce: String?, issuer target: URL) async throws -> String {
        guard supports(issuer: target), let nonce, !nonce.isEmpty else { throw WalletError.unsupportedKeyAttestation }
        let jwt = try await request(.key, key: holderKey, nonce: nonce)
        try Self.checkContract(jwt, now: now(), requireIssuedAt: false)
        return jwt
    }

    /// What the contract asks beyond the generic validators: no extended key usage anywhere in the
    /// chain (the Authrim OP refuses it) and, for a wallet attestation, `iat` and a life of at most 24 h.
    static func checkContract(_ jwt: String, now: Date, requireIssuedAt: Bool = true) throws {
        let refused = WalletError.invalidIssuer("The wallet provider's answer breaks the provider contract.")
        guard let parts = JWS.parse(jwt), let chain = parts.header["x5c"] as? [String], (1...8).contains(chain.count)
        else { throw refused }
        for encoded in chain {
            guard let der = Data(base64Encoded: encoded), !CertificateKeyIdentifiers.hasExtension(
                oid: [0x55, 0x1D, 0x25], in: der) else { throw refused } // 2.5.29.37 extKeyUsage
        }
        if requireIssuedAt {
            guard let iat = (parts.payload["iat"] as? NSNumber)?.doubleValue,
                  let exp = (parts.payload["exp"] as? NSNumber)?.doubleValue,
                  exp > iat, exp - iat <= 86_400 else { throw refused }
        }
    }

    // MARK: Contract

    /// One request at a time per wallet: registration, assertion counters and the provider's reply
    /// order must not interleave (a lower counter arriving after a higher one is refused).
    private func request(_ purpose: Purpose, key: PublicJWK, nonce: String?) async throws -> String {
        await gate.acquire()
        do {
            let jwt = try await performRequest(purpose, key: key, nonce: nonce)
            await gate.release()
            return jwt
        } catch {
            await gate.release()
            throw error
        }
    }

    private func performRequest(_ purpose: Purpose, key: PublicJWK, nonce: String?) async throws -> String {
        for attempt in 0..<2 {
            let keyID = try await registeredKeyID()
            let challenge = try await newChallenge()
            let hash = Self.clientDataHash(
                purpose: purpose, challenge: challenge, thumbprint: key.thumbprint, nonce: nonce)
            let assertion: Data
            do {
                assertion = try await appAttest.generateAssertion(keyID, clientDataHash: hash)
            } catch {
                // The key is gone (restore, reinstall): register a new one once.
                state.clear()
                if attempt == 0 { continue }
                throw WalletError.keyUnavailable("App Attest could not sign the request.")
            }
            var body: [String: Any] = [
                "key_id": keyID, "challenge": challenge, "purpose": purpose.rawValue,
                "assertion": assertion.base64EncodedString(), "jwk": key.proofMembers,
            ]
            if let nonce { body["nonce"] = nonce }
            let response = try await post(purpose.rawValue, body)
            if response.status == 401, response.errorCode == "unknown_key", attempt == 0 {
                state.clear()
                continue
            }
            guard response.status == 200,
                  let object = (try? JSONSerialization.jsonObject(with: response.data)) as? [String: Any],
                  let jwt = object["attestation"] as? String, !jwt.isEmpty
            else {
                throw WalletError.network("The wallet provider refused the request (HTTP \(response.status)).")
            }
            return jwt
        }
        throw WalletError.network("The wallet provider could not register this app instance.")
    }

    /// `SHA-256` of the contract's client data string: provider, purpose, one-time challenge, the
    /// RFC 7638 thumbprint of the key to attest and, for a key attestation, the issuer's `c_nonce`.
    static func clientDataHash(purpose: Purpose, challenge: String, thumbprint: Data, nonce: String?) -> Data {
        var text = "authrim-wallet-provider/v1\n\(purpose.rawValue)\n\(challenge)\n\(Base64URL.encode(thumbprint))"
        if let nonce { text += "\n" + nonce }
        return Data(SHA256.hash(data: Data(text.utf8)))
    }

    private func registeredKeyID() async throws -> String {
        let existing = state.load()
        if let existing, existing.registered { return existing.keyID }
        guard appAttest.isSupported else { throw WalletError.unsupportedKeyAttestation }
        // An interrupted registration resumes with its key, challenge and, once Apple answered, its
        // attestation (Apple asks for the same key and hash after `serverUnavailable`).
        var current: AppAttestState
        if let existing { current = existing } else {
            current = AppAttestState(keyID: try await appAttest.generateKey(), registered: false)
            try state.save(current)
        }
        let keyID = current.keyID
        let challenge: String
        if let saved = current.challenge { challenge = saved } else {
            challenge = try await newChallenge()
            current.challenge = challenge
            try state.save(current)
        }
        let attestationText: String
        if let saved = current.attestation {
            attestationText = saved
        } else {
            do {
                let data = try await appAttest.attestKey(
                    keyID, clientDataHash: Data(SHA256.hash(data: Data(challenge.utf8))))
                attestationText = data.base64EncodedString()
            } catch {
                if (error as? DCError)?.code == .serverUnavailable {
                    throw WalletError.network("Apple's attestation service is unavailable. Try again later.")
                }
                state.clear()
                throw WalletError.keyUnavailable("App Attest could not attest this app instance.")
            }
            current.attestation = attestationText
            try state.save(current)
        }
        // A transport failure keeps the saved attestation for the next try; a refusal drops the key.
        let response = try await post("register", [
            "key_id": keyID, "challenge": challenge, "attestation_object": attestationText,
        ])
        guard response.status == 200 else {
            // A busy or failing provider keeps the saved attestation (the registration is idempotent for
            // the same key, challenge and attestation); only a definite refusal drops the key.
            let temporary = [408, 425, 429].contains(response.status) || response.status >= 500
            if !temporary { state.clear() }
            throw WalletError.network("The wallet provider did not accept this app instance (HTTP \(response.status)).")
        }
        try state.save(AppAttestState(keyID: keyID, registered: true))
        return keyID
    }

    private func newChallenge() async throws -> String {
        let response = try await post("challenge", [:])
        guard response.status == 200,
              let object = (try? JSONSerialization.jsonObject(with: response.data)) as? [String: Any],
              let challenge = object["challenge"] as? String,
              (16...512).contains(challenge.utf8.count),
              challenge.utf8.allSatisfy({ (0x20...0x7e).contains($0) })
        else { throw WalletError.network("The wallet provider gave no usable challenge.") }
        return challenge
    }

    private func post(_ path: String, _ body: [String: Any]) async throws -> WalletHTTPResponse {
        let url = origin.appendingPathComponent(path)
        return try await http.send(
            url, method: "POST", headers: ["Content-Type": "application/json"],
            body: try JSONSerialization.data(withJSONObject: body), origin: origin)
    }

    /// A FIFO async mutex.
    private actor Gate {
        private var busy = false
        private var waiters: [CheckedContinuation<Void, Never>] = []
        func acquire() async {
            if !busy { busy = true; return }
            await withCheckedContinuation { waiters.append($0) }
        }
        func release() {
            if waiters.isEmpty { busy = false } else { waiters.removeFirst().resume() }
        }
    }
}

/// The key attestation roots are the pinned provider roots, never taken from the attestation.
nonisolated struct PinnedKeyAttestationTrust: KeyAttestationTrustSource {
    let roots: [Data]
    let issuers: Set<String>
    func trustedRoots(for attestation: String, issuer: URL) async throws -> [Data] {
        guard issuers.contains(issuer.absoluteString), !roots.isEmpty else {
            throw WalletError.unsupportedKeyAttestation
        }
        return roots
    }
}

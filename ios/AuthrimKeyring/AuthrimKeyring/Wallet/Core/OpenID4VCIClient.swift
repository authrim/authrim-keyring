import Foundation

/// Runs the OpenID4VCI 1.0 pre-authorized code flow: offer, metadata, token, nonce, proof, credential,
/// verification, storage. Secrets (access token, proof, `tx_code`) only go to endpoints on the credential
/// issuer's origin (`WalletHTTP` enforces it per request). The access token is never logged or stored.
nonisolated final class OpenID4VCIClient: CredentialIssuanceService {
    private let http: WalletHTTP
    private let store: any CredentialStore
    private let makeKey: @Sendable (String) throws -> any HolderSigning
    private let existingKey: @Sendable (String, PublicJWK) -> any HolderSigning
    private let deleteKey: @Sendable (String) -> Void
    private let now: @Sendable () -> Date
    private let languages: @Sendable () -> [String]
    private let sessions = OfferSessions()

    init(
        http: WalletHTTP = WalletHTTP(),
        store: any CredentialStore = KeychainCredentialStore(),
        makeKey: @escaping @Sendable (String) throws -> any HolderSigning = { try HolderKey.create(tag: $0) },
        existingKey: @escaping @Sendable (String, PublicJWK) -> any HolderSigning = {
            ExistingHolderKey(
                tag: $0, publicJWK: $1,
                reason: String(localized: "Renew your admin credential with the key on this iPhone."))
        },
        deleteKey: @escaping @Sendable (String) -> Void = { try? HolderKey.delete(tag: $0) },
        now: @escaping @Sendable () -> Date = { Date() },
        languages: @escaping @Sendable () -> [String] = { Locale.preferredLanguages }
    ) {
        self.http = http
        self.store = store
        self.makeKey = makeKey
        self.existingKey = existingKey
        self.deleteKey = deleteKey
        self.now = now
        self.languages = languages
    }

    // MARK: Preview

    func preview(offer: String) async throws -> CredentialOfferPreview {
        let parsed = try await CredentialOfferParser.resolve(offer, http: http)
        let verified = try await IssuerMetadata.resolve(offer: parsed, http: http, preferredLanguages: languages())
        let requirement = parsed.transactionCode.map { code in
            TransactionCodeRequirement(
                length: code.length.flatMap { (1...64).contains($0) ? $0 : nil },
                numeric: (code.inputMode ?? "numeric") == "numeric",
                description: code.description.flatMap { IssuerMetadata.sanitize(String($0.prefix(300))) })
        }
        // A credential this device already holds for this issuer, bound to a key the offer names
        // (the admin's registered second factor): renewed with that key so the factor carries over.
        // With a hint, a failed read is an error: issuing with a new key instead would silently lose
        // the second factor the renewal is meant to keep.
        let hints = HolderKeyRenewal.hints(in: offer)
        var renewal: StoredCredential?
        if !hints.isEmpty {
            let stored = try store.loadAllCountingSkipped()
            renewal = HolderKeyRenewal.renewable(
                from: stored.items, issuer: verified.issuer, vct: verified.configuration.vct, hints: hints)
            // The credential to renew may be the one that could not be read.
            if renewal == nil && stored.skipped > 0 {
                throw WalletError.storage(String(localized: "A stored credential could not be read, so Keyring cannot tell whether to renew it."))
            }
        }
        let preview = CredentialOfferPreview(
            id: UUID(), issuer: verified.issuer, issuerDisplayName: verified.displayName,
            credentialConfigurationId: verified.configuration.id, credentialName: verified.configuration.name,
            claimNames: verified.configuration.claimNames, transactionCode: requirement,
            renewsCredential: renewal != nil)
        await sessions.put(
            preview.id, PendingOffer(preAuthorizedCode: parsed.preAuthorizedCode, issuer: verified, renewal: renewal))
        return preview
    }

    // MARK: Issue

    func issue(_ preview: CredentialOfferPreview, transactionCode: String?) async throws -> StoredCredential {
        guard let pending = await sessions.get(preview.id) else {
            throw WalletError.invalidIssuer("This offer is no longer available. Scan it again.")
        }
        let issuer = pending.issuer
        // From before the token request (which spends the offer) until this returns, deleting the
        // credential being renewed keeps its key: the renewal signs with it.
        if let renewal = pending.renewal { HolderKeyReservations.shared.reserve(renewal.keyTag) }
        defer { if let renewal = pending.renewal { HolderKeyReservations.shared.release(renewal.keyTag) } }
        // With the key reserved, it is still there only if a credential still uses it: otherwise stop
        // before the token request spends the offer.
        if let renewal = pending.renewal, try !store.loadAll().contains(where: { $0.keyTag == renewal.keyTag }) {
            await sessions.remove(preview.id)
            throw WalletError.storage(String(localized: "The credential to renew was removed. Create a new offer in the admin console."))
        }
        let code = transactionCode?.trimmingCharacters(in: .whitespacesAndNewlines)
        if preview.transactionCode != nil, code?.isEmpty != false { throw WalletError.transactionCodeRequired }

        let accessToken: String
        do {
            accessToken = try await requestToken(pending, transactionCode: preview.transactionCode == nil ? nil : code)
        } catch WalletError.outcomeUnknown(let detail) {
            // The code may already be spent on the issuer: never exchange it again.
            await sessions.remove(preview.id)
            throw WalletError.offerConsumed(detail)
        }
        // From here the pre-authorized code is spent. Any failure is final for this offer: a retry would
        // only be refused (or burn another code), so the offer is dropped and the user needs a new one.
        do {
            let credential = try await complete(issuer, accessToken: accessToken, renewal: pending.renewal)
            await sessions.remove(preview.id)
            return credential
        } catch {
            await sessions.remove(preview.id)
            throw WalletError.offerConsumed(Self.cause(of: error))
        }
    }

    /// Nonce, proof, credential, verification and storage, after the token step.
    private func complete(
        _ issuer: VerifiedIssuer, accessToken: String, renewal: StoredCredential?
    ) async throws -> StoredCredential {
        let nonce = try await requestNonce(issuer)

        // A renewal signs with the key the earlier credential uses; it is never deleted here, as that
        // credential still needs it.
        let reused = renewal.flatMap { old in HolderKeyRenewal.holderKey(of: old).map { (old.keyTag, $0) } }
        let tag = reused?.0 ?? HolderKey.makeTag()
        let signed = try await createProof(
            tag: tag, existing: reused?.1, audience: issuer.issuer.absoluteString, nonce: nonce)
        let signer = signed.signer
        do {
            let sdJwt = try await requestCredential(issuer, accessToken: accessToken, proof: signed.proof)
            let verified = try await verify(sdJwt, issuer: issuer, holderKey: signer.publicJWK)
            let credential = StoredCredential(
                id: UUID(), issuer: issuer.issuer, issuerDisplayName: issuer.displayName,
                credentialConfigurationId: issuer.configuration.id, vct: issuer.configuration.vct,
                credentialName: issuer.configuration.name, claims: verified.claims,
                issuedAt: verified.issuedAt ?? now(), expiresAt: verified.expiresAt, keyTag: tag,
                confirmationCode: signer.publicJWK.confirmationCode, sdJwt: sdJwt,
                // The same key is the same second factor, as recorded now (not when the offer was read).
                // A registration known when the offer was read is never dropped (the renewed
                // credential may have been deleted meanwhile).
                secondFactorRegisteredAt: reused == nil
                    ? nil : [registeredAt(keyTag: tag), renewal?.secondFactorRegisteredAt].compactMap { $0 }.min())
            do { try store.save(credential) } catch let error as WalletError { throw error } catch {
                throw WalletError.storage(error.localizedDescription)
            }
            return credential
        } catch {
            if reused == nil { deleteKey(tag) }
            throw error
        }
    }

    /// When the admin console accepted the key under `keyTag`, from the stored credentials using it.
    private func registeredAt(keyTag: String) -> Date? {
        ((try? store.loadAll()) ?? []).filter { $0.keyTag == keyTag }.compactMap(\.secondFactorRegisteredAt).min()
    }

    /// Creates the holder key (or takes the existing one of a renewal) and signs the proof. `@concurrent` keeps both off the main actor: the
    /// Secure Enclave calls block while Face ID / the passcode prompt is up, and any key created before a
    /// failure is deleted here.
    @concurrent
    private func createProof(tag: String, existing: PublicJWK?, audience: String, nonce: String?) async throws
        -> (signer: any HolderSigning, proof: String)
    {
        let signer = try existing.map { existingKey(tag, $0) } ?? makeKey(tag)
        do {
            let proof = try ProofJWT.make(
                audience: audience, nonce: nonce, issuedAt: now(), key: signer.publicJWK, sign: signer.sign)
            return (signer, proof)
        } catch {
            if existing == nil { deleteKey(tag) }
            throw error
        }
    }

    private static func cause(of error: Error) -> String {
        switch error as? WalletError {
        case .network(let text), .invalidIssuer(let text), .invalidCredential(let text),
             .keyUnavailable(let text), .storage(let text), .offerConsumed(let text):
            return text
        case .some(let other):
            return String(describing: other)
        case .none:
            return error.localizedDescription
        }
    }

    // MARK: Protocol steps

    private func requestToken(_ pending: PendingOffer, transactionCode: String?) async throws -> String {
        var fields = [("grant_type", CredentialOfferParser.preAuthorizedGrant), ("pre-authorized_code", pending.preAuthorizedCode)]
        if let transactionCode { fields.append(("tx_code", transactionCode)) }
        let issuer = pending.issuer
        let response = try await http.send(
            issuer.tokenEndpoint, method: "POST",
            headers: ["Content-Type": "application/x-www-form-urlencoded"],
            body: WalletHTTP.formBody(fields), origin: issuer.issuer)
        guard response.status == 200 else {
            switch response.errorCode {
            case "invalid_grant": throw WalletError.offerRejected
            case "invalid_request": throw WalletError.transactionCodeRequired
            default: throw WalletError.network("The token request failed (HTTP \(response.status)).")
            }
        }
        guard let object = (try? JSONSerialization.jsonObject(with: response.data)) as? [String: Any],
              let token = object["access_token"] as? String, !token.isEmpty,
              (object["token_type"] as? String)?.lowercased() == "bearer"
        else {
            // A 200 means the issuer accepted (and spent) the code, even if the body is unusable.
            throw WalletError.outcomeUnknown("The token response is not a bearer token.")
        }
        return token
    }

    private func requestNonce(_ issuer: VerifiedIssuer) async throws -> String? {
        guard let endpoint = issuer.nonceEndpoint else { return nil }
        let response = try await http.send(endpoint, method: "POST", origin: issuer.issuer)
        guard response.status == 200,
              let object = (try? JSONSerialization.jsonObject(with: response.data)) as? [String: Any],
              let nonce = object["c_nonce"] as? String, !nonce.isEmpty
        else { throw WalletError.network("The nonce request failed (HTTP \(response.status)).") }
        return nonce
    }

    private func requestCredential(_ issuer: VerifiedIssuer, accessToken: String, proof: String) async throws -> String {
        let body: [String: Any] = [
            "credential_configuration_id": issuer.configuration.id,
            "proofs": ["jwt": [proof]],
        ]
        let response = try await http.send(
            issuer.credentialEndpoint, method: "POST",
            headers: ["Content-Type": "application/json", "Authorization": "Bearer \(accessToken)"],
            body: try JSONSerialization.data(withJSONObject: body), maxBytes: WalletHTTP.credentialLimit,
            origin: issuer.issuer)
        guard response.status == 200 else {
            let reason = response.status == 401 ? "invalid_token" : (response.errorCode ?? "HTTP \(response.status)")
            throw WalletError.network("The credential request was rejected (\(reason)).")
        }
        guard let object = (try? JSONSerialization.jsonObject(with: response.data)) as? [String: Any],
              let credentials = object["credentials"] as? [[String: Any]], credentials.count == 1,
              let credential = credentials[0]["credential"] as? String
        else { throw WalletError.invalidCredential("The credential response is malformed.") }
        return credential
    }

    /// Checks the credential against the issuer's published key and everything the wallet asked for.
    private func verify(_ text: String, issuer: VerifiedIssuer, holderKey: PublicJWK) async throws -> VerifiedCredential {
        let parsed = try ParsedSDJWT(text)
        let kid = try SDJWTVerifier.keyID(of: parsed)
        guard let url = IssuerMetadata.wellKnownURL(for: issuer.issuer, suffix: "jwt-vc-issuer") else {
            throw WalletError.invalidIssuer("The issuer key URL cannot be built.")
        }
        let metadata = try await http.getJSON(url, origin: issuer.issuer)
        guard (metadata["issuer"] as? String) == issuer.issuer.absoluteString,
              let keys = (metadata["jwks"] as? [String: Any])?["keys"] as? [[String: Any]]
        else { throw WalletError.invalidIssuer("The issuer key set does not belong to this issuer.") }
        let candidates = keys.compactMap { PublicJWK(from: $0) }.filter { $0.kid == kid }
        guard candidates.count == 1, let key = candidates.first else {
            throw WalletError.invalidCredential("The issuer publishes no single key for this credential.")
        }
        return try SDJWTVerifier.verify(
            parsed, issuerKey: key, expectedIssuer: issuer.issuer.absoluteString,
            expectedVct: issuer.configuration.vct, holderKey: holderKey, now: now())
    }
}

// MARK: - Offers between preview and issue

nonisolated struct PendingOffer: Sendable {
    let preAuthorizedCode: String
    let issuer: VerifiedIssuer
    /// The stored credential whose holder key the new one is bound to, for a renewal.
    var renewal: StoredCredential? = nil
}

/// The verified offers waiting for the user's decision. The pre-authorized code stays here, out of the preview.
private actor OfferSessions {
    private var offers: [UUID: PendingOffer] = [:]
    private var order: [UUID] = []
    private let limit = 8

    func put(_ id: UUID, _ offer: PendingOffer) {
        offers[id] = offer
        order.append(id)
        while order.count > limit { offers[order.removeFirst()] = nil }
    }

    func get(_ id: UUID) -> PendingOffer? { offers[id] }

    func remove(_ id: UUID) {
        offers[id] = nil
        order.removeAll { $0 == id }
    }
}

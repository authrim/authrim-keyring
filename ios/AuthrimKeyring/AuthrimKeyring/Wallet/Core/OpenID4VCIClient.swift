import Foundation

/// Runs OpenID4VCI 1.0 issuance: offer, metadata, authorization, token, nonce, proof, credential,
/// verification, storage. Secrets go only to metadata-verified endpoints. The access token is never
/// logged or stored.
nonisolated final class OpenID4VCIClient: CredentialIssuanceService {
    private let http: WalletHTTP
    private let store: any CredentialStore
    private let makeKey: @Sendable (String) throws -> any HolderSigning
    private let existingKey: @Sendable (String, PublicJWK) -> any HolderSigning
    private let deleteKey: @Sendable (String) -> Void
    private let now: @Sendable () -> Date
    private let languages: @Sendable () -> [String]
    private let typeMetadataRegistry: TypeMetadataRegistry
    private let keyAttestationProvider: (any KeyAttestationProvider)?
    private let keyAttestationTrustSource: (any KeyAttestationTrustSource)?
    private let walletAttestationProvider: (any WalletAttestationProvider)?
    private let issuerCertificateTrustSource: (any IssuerCertificateTrustSource)?
    private let authorizationBrowser: (any AuthorizationBrowser)?
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
        languages: @escaping @Sendable () -> [String] = { Locale.preferredLanguages },
        typeMetadataRegistry: TypeMetadataRegistry = .eudiTest,
        keyAttestationProvider: (any KeyAttestationProvider)? = nil,
        keyAttestationTrustSource: (any KeyAttestationTrustSource)? = nil,
        walletAttestationProvider: (any WalletAttestationProvider)? = nil,
        issuerCertificateTrustSource: (any IssuerCertificateTrustSource)? = nil,
        authorizationBrowser: (any AuthorizationBrowser)? = nil
    ) {
        self.http = http
        self.store = store
        self.makeKey = makeKey
        self.existingKey = existingKey
        self.deleteKey = deleteKey
        self.now = now
        self.languages = languages
        self.typeMetadataRegistry = typeMetadataRegistry
        self.keyAttestationProvider = keyAttestationProvider
        self.keyAttestationTrustSource = keyAttestationTrustSource
        self.walletAttestationProvider = walletAttestationProvider
        self.issuerCertificateTrustSource = issuerCertificateTrustSource
        self.authorizationBrowser = authorizationBrowser
    }

    // MARK: Preview

    func preview(offer: String) async throws -> CredentialOfferPreview {
        let isHAIPOffer = offer.trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased().hasPrefix("haip-vci:")
        let parsed = try await CredentialOfferParser.resolve(offer, http: http)
        let supportsKeyAttestation = URL(string: parsed.credentialIssuer).map {
            keyAttestationProvider?.supports(issuer: $0) == true && keyAttestationTrustSource != nil
        } == true
        let supportsWalletAttestation = URL(string: parsed.credentialIssuer).map {
            walletAttestationProvider?.supports(issuer: $0) == true
        } == true
        let verified = try await IssuerMetadata.resolve(
            offer: parsed, http: http, preferredLanguages: languages(),
            supportsKeyAttestation: supportsKeyAttestation,
            canAuthenticateWithWalletAttestation: supportsWalletAttestation,
            isHAIPOffer: isHAIPOffer)
        // A configured ecosystem certificate policy applies to its issuer and credential type
        // regardless of the untrusted QR wrapper. HAIP links additionally require a policy for
        // every supported configuration before the one-time code is redeemed.
        let x509ConfigurationIDs = Set(verified.configurations.compactMap { configuration in
            issuerCertificateTrustSource?.supports(issuer: verified.issuer, vct: configuration.vct) == true
                ? configuration.id : nil
        })
        if isHAIPOffer {
            guard x509ConfigurationIDs.count == verified.configurations.count else {
                throw WalletError.unsupportedIssuerCertificateTrust
            }
        }
        // Check that a configured ecosystem list is independently trusted and still fresh before
        // presenting a one-time-code offer. Recheck at issuance in case it expires meanwhile.
        if let issuerCertificateTrustSource {
            for configuration in verified.configurations where x509ConfigurationIDs.contains(configuration.id) {
                try await issuerCertificateTrustSource.prepare(issuer: verified.issuer, vct: configuration.vct)
            }
        }
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
        var renewals: [String: StoredCredential] = [:]
        if !hints.isEmpty {
            let stored = try store.loadAllCountingSkipped()
            for configuration in verified.configurations {
                if let renewal = HolderKeyRenewal.renewable(
                    from: stored.items, issuer: verified.issuer, vct: configuration.vct, hints: hints)
                {
                    renewals[configuration.id] = renewal
                } else if stored.skipped > 0 {
                    // An unreadable item may be the renewal for this configuration. Never silently
                    // issue it with a new key and lose the registered second factor.
                    throw WalletError.storage(String(localized: "A stored credential could not be read, so Keyring cannot tell whether to renew it."))
                }
            }
        }
        let preview = CredentialOfferPreview(
            id: UUID(), issuer: verified.issuer, authorizationServer: verified.authorizationServer,
            issuerDisplayName: verified.displayName, issuerDisplayDirection: verified.displayDirection,
            credential: OfferedCredential(
                id: verified.configuration.id, name: verified.configuration.name,
                claimNames: verified.configuration.claimNames,
                renewsCredential: renewals[verified.configuration.id] != nil,
                nameDirection: verified.configuration.displaySource?.direction,
                claimNameDirections: verified.configuration.claimNameDirections),
            additionalCredentials: verified.additionalConfigurations.map { configuration in
                OfferedCredential(
                    id: configuration.id, name: configuration.name,
                    claimNames: configuration.claimNames, renewsCredential: renewals[configuration.id] != nil,
                    nameDirection: configuration.displaySource?.direction,
                    claimNameDirections: configuration.claimNameDirections)
            },
            transactionCode: requirement,
            authorizationRequired: {
                if case .authorizationCode = parsed.grant { true } else { false }
            }())
        await sessions.put(
            preview.id, PendingOffer(
                grant: parsed.grant, issuer: verified,
                x509ConfigurationIDs: x509ConfigurationIDs, isHAIPOffer: isHAIPOffer,
                renewals: renewals))
        return preview
    }

    // MARK: Issue

    func issue(_ preview: CredentialOfferPreview, transactionCode: String?) async throws -> StoredCredential {
        let issued = try await issueAll(
            preview, selectedConfigurationIds: [preview.credentialConfigurationId], transactionCode: transactionCode)
        return issued[0]
    }

    func issueAll(
        _ preview: CredentialOfferPreview, selectedConfigurationIds: [String], transactionCode: String?
    ) async throws -> [StoredCredential] {
        guard let pending = await sessions.get(preview.id) else {
            throw WalletError.invalidIssuer("This offer is no longer available. Scan it again.")
        }
        let issuer = pending.issuer
        let selected = Set(selectedConfigurationIds)
        let offered = Set(preview.credentials.map(\.id))
        guard !selected.isEmpty, selected.count == selectedConfigurationIds.count,
              selected.isSubset(of: offered), preview.issuer == issuer.issuer,
              selected.isSubset(of: Set(issuer.configurations.map(\.id)))
        else { throw WalletError.invalidIssuer("The selected credentials are not in this offer.") }
        let configurations = issuer.configurations.filter { selected.contains($0.id) }
        // From before the token request (which spends the offer) until this returns, deleting the
        // credential being renewed keeps its key: the renewal signs with it.
        let reservedTags = Set(configurations.compactMap { pending.renewals[$0.id]?.keyTag })
        for tag in reservedTags { HolderKeyReservations.shared.reserve(tag) }
        defer { for tag in reservedTags { HolderKeyReservations.shared.release(tag) } }
        // With the key reserved, it is still there only if a credential still uses it: otherwise stop
        // before the token request spends the offer.
        let currentTags = try Set(store.loadAll().map(\.keyTag))
        if !reservedTags.isSubset(of: currentTags) {
            await sessions.remove(preview.id)
            throw WalletError.storage(String(localized: "The credential to renew was removed. Ask the issuer or offer provider for a new offer."))
        }
        // A text transaction code may contain leading or trailing spaces. Only numeric input
        // receives whitespace normalization, matching the UI's numeric input handling.
        let code = preview.transactionCode?.numeric == true
            ? transactionCode?.trimmingCharacters(in: .whitespacesAndNewlines) : transactionCode
        if preview.transactionCode != nil, code?.isEmpty != false { throw WalletError.transactionCodeRequired }

        // The user may leave the preview open past the list's NextUpdate or a trust-policy
        // change. Recheck every selected type before spending its single-use authorization.
        for configuration in configurations where pending.x509ConfigurationIDs.contains(configuration.id) {
            guard let issuerCertificateTrustSource else {
                throw WalletError.unsupportedIssuerCertificateTrust
            }
            try await issuerCertificateTrustSource.prepare(issuer: issuer.issuer, vct: configuration.vct)
        }

        // Fetch a public issuer nonce and validate each required key attestation before the
        // one-time code is exchanged. The same nonce goes into the later holder proof.
        var prepared: [String: PreparedAttestedKey] = [:]
        defer {
            for key in prepared.values where !key.reused { deleteKey(key.tag) }
        }
        for configuration in configurations where configuration.keyAttestationRequirements != nil {
            prepared[configuration.id] = try await prepareAttestedKey(
                issuer: issuer, configuration: configuration, renewal: pending.renewals[configuration.id])
        }

        // Separate UI flows can hold the same preview; only one may send its single-use code.
        guard await sessions.claim(preview.id) else {
            throw WalletError.invalidIssuer("This offer is already being received. Wait for its result.")
        }
        let authorization: TokenAuthorization
        do {
            let authorizationCode: AuthorizationCodeResult?
            if case .authorizationCode = pending.grant {
                authorizationCode = try await authorize(pending, configurations: configurations)
            } else {
                authorizationCode = nil
            }
            // Browser authorization can outlast the trust-list update deadline. Do not
            // exchange its code against a list that became invalid while the user signed in.
            for configuration in configurations where pending.x509ConfigurationIDs.contains(configuration.id) {
                guard let issuerCertificateTrustSource else {
                    throw WalletError.unsupportedIssuerCertificateTrust
                }
                try await issuerCertificateTrustSource.prepare(issuer: issuer.issuer, vct: configuration.vct)
            }
            authorization = try await requestToken(
                pending, transactionCode: preview.transactionCode == nil ? nil : code,
                authorizationCode: authorizationCode)
        } catch WalletError.outcomeUnknown(let detail) {
            // The code may already be spent on the issuer: never exchange it again.
            await sessions.remove(preview.id)
            throw WalletError.offerConsumed(detail)
        } catch WalletError.offerRejected {
            // An invalid grant means the code cannot be used again. Only a specifically
            // identified incorrect transaction code remains in the session for correction.
            await sessions.remove(preview.id)
            throw WalletError.offerRejected
        } catch {
            // Incorrect transaction codes and definite pre-send failures can be retried.
            await sessions.release(preview.id)
            throw error
        }
        // From here the pre-authorized code is spent. Any failure is final for this offer: a retry would
        // only be refused (or burn another code), so the offer is dropped and the user needs a new one.
        do {
            // Check the whole selection before issuing any credential. A token that authorizes
            // only some requested configurations must not cause an avoidable partial issuance.
            for configuration in configurations {
                _ = try authorization.identifiers(for: configuration.id)
            }
        } catch {
            await sessions.remove(preview.id)
            throw WalletError.offerConsumed(Self.cause(of: error))
        }
        var issued: [StoredCredential] = []
        for configuration in configurations {
            let identifiers = try authorization.identifiers(for: configuration.id)
            for (index, identifier) in identifiers.enumerated() {
                var additionalKey: PreparedAttestedKey?
                do {
                    // The token can authorize several datasets of one configuration. Give
                    // each dataset its own holder key and nonce so they are not linkable.
                    // Only the first key can be attested before token exchange because the
                    // number of datasets is learned from the token response.
                    if index > 0, configuration.keyAttestationRequirements != nil {
                        additionalKey = try await prepareAttestedKey(
                            issuer: issuer, configuration: configuration, renewal: nil)
                    }
                    let credential = try await complete(
                        issuer, configuration: configuration, authorization: authorization,
                        credentialIdentifier: identifier,
                        renewal: index == 0 ? pending.renewals[configuration.id] : nil,
                        prepared: index == 0 ? prepared[configuration.id] : additionalKey,
                        requiresX509IssuerTrust: pending.x509ConfigurationIDs.contains(configuration.id))
                    issued.append(credential)
                    if index == 0 { prepared.removeValue(forKey: configuration.id) }
                    additionalKey = nil
                } catch {
                    if let additionalKey, !additionalKey.reused { deleteKey(additionalKey.tag) }
                    await sessions.remove(preview.id)
                    if !issued.isEmpty {
                        throw PartialIssuanceError(
                            saved: issued, failedCredentialName: configuration.name, reason: Self.cause(of: error))
                    }
                    throw WalletError.offerConsumed(Self.cause(of: error))
                }
            }
        }
        await sessions.remove(preview.id)
        return issued
    }

    /// Nonce, proof, credential, verification and storage, after the token step.
    private func complete(
        _ issuer: VerifiedIssuer, configuration: VerifiedConfiguration, authorization: TokenAuthorization,
        credentialIdentifier: String?, renewal: StoredCredential?, prepared: PreparedAttestedKey?,
        requiresX509IssuerTrust: Bool
    ) async throws -> StoredCredential {
        let nonce: String?
        if let prepared {
            nonce = prepared.nonce
        } else {
            nonce = try await requestNonce(issuer, dpop: authorization.dpop)
        }

        // A renewal signs with the key the earlier credential uses; it is never deleted here, as that
        // credential still needs it.
        let reused = renewal.flatMap { old in HolderKeyRenewal.holderKey(of: old).map { (old.keyTag, $0) } }
        let tag = prepared?.tag ?? reused?.0 ?? HolderKey.makeTag()
        let signed = try await createProof(
            tag: tag, existing: reused?.1, prepared: prepared,
            audience: issuer.issuer.absoluteString, nonce: nonce)
        let signer = signed.signer
        do {
            let sdJwt: String
            do {
                sdJwt = try await requestCredential(
                    issuer, configuration: configuration, credentialIdentifier: credentialIdentifier,
                    authorization: authorization, proof: signed.proof)
            } catch CredentialNonceError.rejected {
                // A preflight nonce can expire during wallet attestation, token exchange or
                // device authentication. Refresh the attestation and proof with the same key;
                // the access token remains valid and the one-time code is never retried.
                guard issuer.nonceEndpoint != nil else {
                    throw WalletError.invalidCredential("The credential nonce was rejected.")
                }
                let freshNonce = try await requestNonce(issuer, dpop: authorization.dpop)
                let freshAttestation: String?
                if let prepared, let requirements = configuration.keyAttestationRequirements {
                    freshAttestation = try await attest(
                        signer: prepared.signer, nonce: freshNonce, issuer: issuer,
                        requirements: requirements)
                } else {
                    freshAttestation = nil
                }
                let freshProof = try await signProof(
                    signer: signer, audience: issuer.issuer.absoluteString,
                    nonce: freshNonce, keyAttestation: freshAttestation)
                do {
                    sdJwt = try await requestCredential(
                        issuer, configuration: configuration, credentialIdentifier: credentialIdentifier,
                        authorization: authorization, proof: freshProof)
                } catch CredentialNonceError.rejected {
                    throw WalletError.invalidCredential("The credential nonce was rejected again.")
                }
            }
            let verified = try await verify(
                sdJwt, issuer: issuer, configuration: configuration, holderKey: signer.publicJWK,
                requiresX509IssuerTrust: requiresX509IssuerTrust)
            if let renewal, reused != nil, !HolderKeyRenewal.isSameAdministrator(sdJwt, as: renewal) {
                throw WalletError.invalidCredential(String(localized: "The renewed credential is for another administrator, so it was not saved."))
            }
            let card = try await CredentialDisplayMetadata.resolve(
                issuerSource: configuration.displaySource, sdJwt: sdJwt, vct: configuration.vct,
                issuerLogo: issuer.issuerLogo, issuerClaimSources: configuration.claimDisplaySources,
                issuer: issuer.issuer, registry: typeMetadataRegistry,
                http: http, languages: languages(), verified: verified)
            var credential = StoredCredential(
                id: UUID(), issuer: issuer.issuer, issuerDisplayName: issuer.displayName,
                credentialConfigurationId: configuration.id, vct: configuration.vct,
                credentialName: card.name ?? configuration.name, claims: verified.claims,
                issuedAt: verified.issuedAt ?? now(), expiresAt: verified.expiresAt, keyTag: tag,
                confirmationCode: signer.publicJWK.confirmationCode, sdJwt: sdJwt,
                // The same key is the same second factor, as recorded now (not when the offer was read).
                // A registration known when the offer was read is never dropped (the renewed
                // credential may have been deleted meanwhile).
                secondFactorRegisteredAt: reused == nil
                    ? nil : [registeredAt(keyTag: tag), renewal?.secondFactorRegisteredAt].compactMap { $0 }.min(),
                credentialDisplay: card.display)
            credential.issuerDisplayDirection = issuer.displayDirection
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
    private func createProof(
        tag: String, existing: PublicJWK?, prepared: PreparedAttestedKey?,
        audience: String, nonce: String?
    ) async throws
        -> (signer: any HolderSigning, proof: String)
    {
        let signer = try prepared?.signer ?? existing.map { existingKey(tag, $0) } ?? makeKey(tag)
        do {
            let proof = try ProofJWT.make(
                audience: audience, nonce: nonce, issuedAt: now(), key: signer.publicJWK,
                keyAttestation: prepared?.attestation, sign: signer.sign)
            return (signer, proof)
        } catch {
            if existing == nil { deleteKey(tag) }
            throw error
        }
    }

    @concurrent
    private func signProof(
        signer: any HolderSigning, audience: String, nonce: String?, keyAttestation: String?
    ) async throws -> String {
        try ProofJWT.make(
            audience: audience, nonce: nonce, issuedAt: now(), key: signer.publicJWK,
            keyAttestation: keyAttestation, sign: signer.sign)
    }

    /// The provider attests a public holder key, while an independent trust source supplies the
    /// accepted CA root. The holder proof is signed later with the same private key and nonce.
    /// The public test provider does not validate platform key properties.
    @concurrent
    private func prepareAttestedKey(
        issuer: VerifiedIssuer, configuration: VerifiedConfiguration, renewal: StoredCredential?
    ) async throws -> PreparedAttestedKey {
        guard let requirements = configuration.keyAttestationRequirements,
              keyAttestationProvider?.supports(issuer: issuer.issuer) == true,
              keyAttestationTrustSource != nil else {
            throw WalletError.unsupportedKeyAttestation
        }
        let nonce = try await requestNonce(issuer, dpop: nil)
        let reused = renewal.flatMap { old in
            HolderKeyRenewal.holderKey(of: old).map { (old.keyTag, $0) }
        }
        let tag = reused?.0 ?? HolderKey.makeTag()
        let signer = try reused.map { existingKey(tag, $0.1) } ?? makeKey(tag)
        do {
            let verified = try await attest(
                signer: signer, nonce: nonce, issuer: issuer, requirements: requirements)
            return PreparedAttestedKey(
                tag: tag, signer: signer, attestation: verified, nonce: nonce, reused: reused != nil)
        } catch {
            if reused == nil { deleteKey(tag) }
            throw error
        }
    }

    @concurrent
    private func attest(
        signer: any HolderSigning, nonce: String?, issuer: VerifiedIssuer,
        requirements: KeyAttestationRequirements
    ) async throws -> String {
        guard let provider = keyAttestationProvider, let trustSource = keyAttestationTrustSource,
              provider.supports(issuer: issuer.issuer) else {
            throw WalletError.unsupportedKeyAttestation
        }
        let attestation = try await provider.attestation(
            for: signer.publicJWK, nonce: nonce, issuer: issuer.issuer)
        let trustedRoots = try await trustSource.trustedRoots(
            for: attestation, issuer: issuer.issuer)
        do {
            return try KeyAttestationVerifier.validate(
                attestation, holderKey: signer.publicJWK, nonce: nonce,
                requirements: requirements, trustedRootDER: trustedRoots, now: now())
        } catch is KeyAttestationValidationError {
            throw WalletError.invalidIssuer("The wallet provider key attestation could not be verified.")
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

    private func clientContext(for issuer: VerifiedIssuer) async throws -> OAuthClientContext {
        let dpopKey = try issuer.supportsDPoP ? WalletDPoPKey() : nil
        let dpop = dpopKey.map(DPoPSession.init)
        var walletAttestation: WalletClientAttestation?
        if issuer.supportsWalletAttestation, let provider = walletAttestationProvider,
           provider.supports(issuer: issuer.issuer) {
            guard let dpopKey else {
                throw WalletError.invalidIssuer("Wallet attestation requires an ES256 DPoP key.")
            }
            // The verified `cnf.jwk` must be the same key used for DPoP and attestation PoP.
            do {
                walletAttestation = try await provider.attestation(
                    for: dpopKey.publicJWK, issuer: issuer.issuer)
            } catch WalletError.outcomeUnknown(let detail) {
                // The provider request carried only a public key. No code has been sent.
                throw WalletError.network(detail)
            }
        }
        return OAuthClientContext(dpopKey: dpopKey, dpop: dpop, walletAttestation: walletAttestation)
    }

    private func authorize(
        _ pending: PendingOffer, configurations: [VerifiedConfiguration]
    ) async throws -> AuthorizationCodeResult {
        guard case .authorizationCode(let issuerState, _) = pending.grant,
              let endpoint = pending.issuer.authorizationEndpoint,
              let parEndpoint = pending.issuer.pushedAuthorizationRequestEndpoint else {
            throw WalletError.invalidIssuer("The authorization endpoints are unavailable.")
        }
        let issuer = pending.issuer
        let context = try await clientContext(for: issuer)
        guard let walletAttestation = context.walletAttestation, let dpopKey = context.dpopKey,
              let dpop = context.dpop else {
            throw WalletError.invalidIssuer("The authorization server requires wallet attestation and DPoP.")
        }
        let verifier = try AuthorizationCodeFlow.randomURLSafeValue()
        let state = try AuthorizationCodeFlow.randomURLSafeValue()
        let useAuthorizationDetails = configurations.contains { $0.scope == nil }
        guard !useAuthorizationDetails || issuer.supportsAuthorizationDetails else {
            throw WalletError.invalidIssuer("The selected credentials need OAuth authorization details support.")
        }
        var seenScopes: Set<String> = []
        let scopes = configurations.compactMap(\.scope).filter { seenScopes.insert($0).inserted }
        var fields: [(String, String)] = [
            ("response_type", "code"),
            ("client_id", walletAttestation.clientID),
            ("redirect_uri", AuthorizationCodeFlow.redirectURI.absoluteString),
            ("resource", issuer.issuer.absoluteString),
            ("state", state),
            ("code_challenge", AuthorizationCodeFlow.challenge(for: verifier)),
            ("code_challenge_method", "S256"),
        ]
        if useAuthorizationDetails {
            let details: [[String: Any]] = configurations.map { configuration in
                var detail: [String: Any] = [
                    "type": "openid_credential",
                    "credential_configuration_id": configuration.id,
                ]
                if issuer.advertisesAuthorizationServers {
                    detail["locations"] = [issuer.issuer.absoluteString]
                }
                return detail
            }
            let data = try JSONSerialization.data(withJSONObject: details, options: [.sortedKeys])
            fields.append(("authorization_details", String(decoding: data, as: UTF8.self)))
        } else {
            fields.append(("scope", scopes.joined(separator: " ")))
        }
        if let issuerState { fields.append(("issuer_state", issuerState)) }
        let body = WalletHTTP.formBody(fields)
        var attestationChallenge: String?
        func sendPAR() async throws -> WalletHTTPResponse {
            var headers = [
                "Content-Type": "application/x-www-form-urlencoded",
                "OAuth-Client-Attestation": walletAttestation.jwt,
                "OAuth-Client-Attestation-PoP": try dpopKey.clientAttestationPoP(
                    clientID: walletAttestation.clientID, audience: issuer.authorizationServer,
                    challenge: attestationChallenge, issuedAt: now()),
            ]
            headers["DPoP"] = try await dpop.proof(
                method: "POST", url: parEndpoint, role: .authorizationServer, issuedAt: now())
            do {
                return try await http.send(
                    parEndpoint, method: "POST", headers: headers, body: body,
                    origin: issuer.authorizationServer)
            } catch WalletError.outcomeUnknown(let detail) {
                // PAR may have created a request URI, but no authorization code exists yet.
                // A fresh PAR request is safe after a response was lost.
                throw WalletError.network(detail)
            } catch is CancellationError {
                throw WalletError.authorizationDenied
            }
        }
        var response = try await sendPAR()
        var retriedDPoP = false
        var retriedAttestation = false
        for _ in 0..<2 where response.status == 400 || response.status == 401 {
            if response.errorCode == "use_dpop_nonce", !retriedDPoP,
               await dpop.remember(response.dpopNonce, from: parEndpoint, role: .authorizationServer) {
                retriedDPoP = true
                response = try await sendPAR()
            } else if response.errorCode == "use_attestation_challenge", !retriedAttestation,
                      let challenge = response.clientAttestationChallenge,
                      !challenge.isEmpty, challenge.utf8.count <= 1_024,
                      challenge.utf8.allSatisfy({ (0x21...0x7e).contains($0) }) {
                retriedAttestation = true
                attestationChallenge = challenge
                response = try await sendPAR()
            } else { break }
        }
        await dpop.remember(response.dpopNonce, from: parEndpoint, role: .authorizationServer)
        guard response.status == 201,
              let object = (try? JSONSerialization.jsonObject(with: response.data)) as? [String: Any],
              let requestURI = object["request_uri"] as? String,
              let lifetime = object["expires_in"] as? NSNumber,
              CFGetTypeID(lifetime) != CFBooleanGetTypeID(),
              lifetime.int64Value > 0,
              lifetime.doubleValue == Double(lifetime.int64Value) else {
            throw WalletError.network("The authorization server rejected the pushed authorization request (HTTP \(response.status)).")
        }
        let url = try AuthorizationCodeFlow.authorizationURL(
            endpoint: endpoint, clientID: walletAttestation.clientID, requestURI: requestURI)
        let browser: any AuthorizationBrowser
        if let authorizationBrowser {
            browser = authorizationBrowser
        } else {
            browser = await MainActor.run { SystemAuthorizationBrowser() }
        }
        let callback = try await browser.authorize(
            url, callbackScheme: AuthorizationCodeFlow.redirectURI.scheme!)
        let code = try AuthorizationCodeFlow.code(
            from: callback, state: state, authorizationServer: issuer.authorizationServer)
        return AuthorizationCodeResult(
            code: code, verifier: verifier, context: context,
            requestedScopes: useAuthorizationDetails ? nil : Set(scopes),
            usedAuthorizationDetails: useAuthorizationDetails)
    }

    private func requestToken(
        _ pending: PendingOffer, transactionCode: String?, authorizationCode: AuthorizationCodeResult?
    ) async throws -> TokenAuthorization {
        let issuer = pending.issuer
        var fields: [(String, String)]
        let context: OAuthClientContext
        switch pending.grant {
        case .preAuthorized(let code, _, _):
            fields = [("grant_type", CredentialOfferParser.preAuthorizedGrant), ("pre-authorized_code", code)]
            if let transactionCode { fields.append(("tx_code", transactionCode)) }
            context = try await clientContext(for: issuer)
        case .authorizationCode:
            guard let authorizationCode else {
                throw WalletError.invalidIssuer("The authorization code is unavailable.")
            }
            fields = [
                ("grant_type", "authorization_code"),
                ("code", authorizationCode.code),
                ("code_verifier", authorizationCode.verifier),
                ("redirect_uri", AuthorizationCodeFlow.redirectURI.absoluteString),
            ]
            if issuer.advertisesAuthorizationServers {
                fields.append(("resource", issuer.issuer.absoluteString))
            }
            context = authorizationCode.context
        }
        let dpopKey = context.dpopKey
        let dpop = context.dpop
        let walletAttestation = context.walletAttestation
        if let walletAttestation {
            fields.append(("client_id", walletAttestation.clientID))
        }
        let body = WalletHTTP.formBody(fields)
        var attestationChallenge: String?
        func sendTokenRequest() async throws -> WalletHTTPResponse {
            var headers = ["Content-Type": "application/x-www-form-urlencoded"]
            if let dpop {
                headers["DPoP"] = try await dpop.proof(
                    method: "POST", url: issuer.tokenEndpoint, role: .authorizationServer, issuedAt: now())
            }
            if let walletAttestation, let dpopKey {
                headers["OAuth-Client-Attestation"] = walletAttestation.jwt
                headers["OAuth-Client-Attestation-PoP"] = try dpopKey.clientAttestationPoP(
                    clientID: walletAttestation.clientID, audience: issuer.authorizationServer,
                    challenge: attestationChallenge, issuedAt: now())
            }
            do {
                return try await http.send(
                    issuer.tokenEndpoint, method: "POST", headers: headers, body: body,
                    origin: issuer.authorizationServer)
            } catch WalletError.network(let detail)
                where detail == "No HTTP response." || detail == "Redirects are not followed." {
                // Both conditions are detected only after URLSession started the POST.
                // The authorization server might already have spent the code.
                throw WalletError.outcomeUnknown(detail)
            } catch is CancellationError {
                // The request may already have reached the server before the task was
                // cancelled (for example, while the app was backgrounded).
                throw WalletError.outcomeUnknown("The token request was cancelled before its result arrived.")
            }
        }
        var response = try await sendTokenRequest()
        // Only explicit OAuth challenges are retried: each mechanism gets at most one retry,
        // using a fresh PoP/DPoP proof while retaining the same key and attestation.
        var retriedDPoP = false
        var retriedAttestation = false
        for _ in 0..<2 where response.status == 400 || response.status == 401 {
            if response.errorCode == "use_dpop_nonce", !retriedDPoP, let dpop,
               await dpop.remember(response.dpopNonce, from: issuer.tokenEndpoint, role: .authorizationServer) {
                retriedDPoP = true
                response = try await sendTokenRequest()
            } else if response.errorCode == "use_attestation_challenge", !retriedAttestation,
                      walletAttestation != nil,
                      let challenge = response.clientAttestationChallenge,
                      !challenge.isEmpty, challenge.utf8.count <= 1_024,
                      challenge.utf8.allSatisfy({ (0x21...0x7e).contains($0) }) {
                retriedAttestation = true
                attestationChallenge = challenge
                response = try await sendTokenRequest()
            } else {
                break
            }
        }
        if let dpop {
            await dpop.remember(response.dpopNonce, from: issuer.tokenEndpoint, role: .authorizationServer)
        }
        guard response.status == 200 else {
            // OAuth errors are authoritative only at token-error status codes. A 5xx
            // body can name any error despite the grant having been consumed.
            switch (response.status == 400 || response.status == 401) ? response.errorCode : nil {
            case "invalid_grant":
                let description = ((try? JSONSerialization.jsonObject(with: response.data)) as? [String: Any])?["error_description"] as? String
                if transactionCode != nil, description?.lowercased().trimmingCharacters(in: .whitespacesAndNewlines) == "invalid tx_code" {
                    throw WalletError.incorrectTransactionCode
                }
                throw WalletError.offerRejected
            case "invalid_request":
                throw WalletError.outcomeUnknown("The authorization server rejected the token request (invalid_request).")
            case "invalid_client", "unsupported_grant_type":
                throw WalletError.outcomeUnknown("The authorization server rejected wallet authentication or the grant type.")
            default:
                // A non-standard error, including a server failure, does not prove the
                // single-use code is still available. The server may have spent it first.
                throw WalletError.outcomeUnknown("The token request outcome is unknown (HTTP \(response.status)).")
            }
        }
        guard let object = (try? JSONSerialization.jsonObject(with: response.data)) as? [String: Any],
              let token = object["access_token"] as? String, !token.isEmpty,
              let rawType = object["token_type"] as? String
        else {
            // A 200 means the issuer accepted (and spent) the code, even if the body is unusable.
            throw WalletError.outcomeUnknown("The token response is not a bearer token.")
        }
        if object["authorization_details"] == nil,
           let requestedScopes = authorizationCode?.requestedScopes,
           let returnedScope = object["scope"] {
            guard let scope = returnedScope as? String,
                  requestedScopes.isSubset(of: Set(scope.split(separator: " ").map(String.init))) else {
                throw WalletError.outcomeUnknown("The token response does not authorize every selected credential scope.")
            }
        }
        if authorizationCode?.usedAuthorizationDetails == true, object["authorization_details"] == nil {
            throw WalletError.outcomeUnknown("The token response omits the requested authorization details.")
        }
        let tokenType: TokenAuthorization.TokenType
        switch rawType.lowercased() {
        case "bearer": tokenType = .bearer
        case "dpop" where dpop != nil: tokenType = .dpop
        default: throw WalletError.outcomeUnknown("The token response has an unsupported token type.")
        }
        if pending.isHAIPOffer, case .bearer = tokenType {
            throw WalletError.outcomeUnknown("The HAIP authorization server returned an unbound access token.")
        }
        let identifiers: [String: [String]]?
        if let detailsValue = object["authorization_details"] {
            guard let details = detailsValue as? [[String: Any]], !details.isEmpty else {
                throw WalletError.outcomeUnknown("The token response has invalid authorization details.")
            }
            var found: [String: [String]] = [:]
            for detail in details where (detail["type"] as? String) == "openid_credential" {
                guard let configurationId = detail["credential_configuration_id"] as? String,
                      !configurationId.isEmpty,
                      let values = detail["credential_identifiers"] as? [String],
                      (1...32).contains(values.count),
                      values.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 512 }),
                      Set(values).count == values.count,
                      found[configurationId] == nil
                else {
                    throw WalletError.outcomeUnknown("The token response has invalid credential identifiers.")
                }
                found[configurationId] = values
            }
            guard !found.isEmpty else {
                throw WalletError.outcomeUnknown("The token response authorizes no credentials.")
            }
            let allIdentifiers = found.values.flatMap { $0 }
            guard Set(allIdentifiers).count == allIdentifiers.count else {
                throw WalletError.outcomeUnknown("The token response reuses a credential identifier.")
            }
            identifiers = found
        } else {
            identifiers = nil
        }
        return TokenAuthorization(
            accessToken: token, tokenType: tokenType, dpop: dpop, credentialIdentifiers: identifiers)
    }

    private func requestNonce(_ issuer: VerifiedIssuer, dpop: DPoPSession?) async throws -> String? {
        guard let endpoint = issuer.nonceEndpoint else { return nil }
        let response = try await http.send(endpoint, method: "POST", origin: endpoint)
        guard response.isSuccess,
              let object = (try? JSONSerialization.jsonObject(with: response.data)) as? [String: Any],
              let nonce = object["c_nonce"] as? String, !nonce.isEmpty
        else { throw WalletError.network("The nonce request failed (HTTP \(response.status)).") }
        if let dpop {
            await dpop.remember(response.dpopNonce, from: endpoint, role: .resourceServer)
        }
        return nonce
    }

    private func requestCredential(
        _ issuer: VerifiedIssuer, configuration: VerifiedConfiguration, credentialIdentifier: String?,
        authorization: TokenAuthorization, proof: String
    ) async throws -> String {
        var body: [String: Any] = ["proofs": ["jwt": [proof]]]
        if let credentialIdentifier {
            body["credential_identifier"] = credentialIdentifier
        } else {
            body["credential_configuration_id"] = configuration.id
        }
        let requestBody = try JSONSerialization.data(withJSONObject: body)
        func sendCredentialRequest() async throws -> WalletHTTPResponse {
            var headers = [
                "Content-Type": "application/json",
                "Authorization": "\(authorization.tokenType.authorizationScheme) \(authorization.accessToken)",
            ]
            if case .dpop = authorization.tokenType {
                guard let dpop = authorization.dpop else {
                    throw WalletError.invalidIssuer("The DPoP token has no matching key.")
                }
                headers["DPoP"] = try await dpop.proof(
                    method: "POST", url: issuer.credentialEndpoint, role: .resourceServer,
                    accessToken: authorization.accessToken, issuedAt: now())
            }
            return try await http.send(
                issuer.credentialEndpoint, method: "POST", headers: headers,
                body: requestBody, maxBytes: WalletHTTP.credentialLimit,
                origin: issuer.credentialEndpoint)
        }
        var response = try await sendCredentialRequest()
        let challenge = response.wwwAuthenticate?.lowercased() ?? ""
        if case .dpop = authorization.tokenType, response.status == 401,
           challenge.contains("dpop"), challenge.contains("use_dpop_nonce"),
           let dpop = authorization.dpop,
           await dpop.remember(response.dpopNonce, from: issuer.credentialEndpoint, role: .resourceServer) {
            response = try await sendCredentialRequest()
        }
        if let dpop = authorization.dpop {
            await dpop.remember(response.dpopNonce, from: issuer.credentialEndpoint, role: .resourceServer)
        }
        guard response.status == 200 else {
            if response.status == 400, response.errorCode == "invalid_nonce" {
                throw CredentialNonceError.rejected
            }
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
    private func verify(
        _ text: String, issuer: VerifiedIssuer, configuration: VerifiedConfiguration, holderKey: PublicJWK,
        requiresX509IssuerTrust: Bool
    ) async throws -> VerifiedCredential {
        let parsed = try ParsedSDJWT(text)
        let key: PublicJWK
        if requiresX509IssuerTrust {
            guard let issuerCertificateTrustSource else {
                throw WalletError.unsupportedIssuerCertificateTrust
            }
            key = try await IssuerX509Verifier.signingKey(
                of: parsed, issuer: issuer.issuer, vct: configuration.vct,
                trustSource: issuerCertificateTrustSource, now: now())
        } else {
            let kid = try SDJWTVerifier.keyID(of: parsed)
            guard let url = IssuerMetadata.wellKnownURL(for: issuer.issuer, suffix: "jwt-vc-issuer") else {
                throw WalletError.invalidIssuer("The issuer key URL cannot be built.")
            }
            let metadata = try await http.getJSON(url, origin: issuer.issuer)
            guard (metadata["issuer"] as? String) == issuer.issuer.absoluteString,
                  let keys = (metadata["jwks"] as? [String: Any])?["keys"] as? [[String: Any]]
            else { throw WalletError.invalidIssuer("The issuer key set does not belong to this issuer.") }
            let candidates = keys.compactMap { PublicJWK(from: $0) }.filter { $0.kid == kid }
            guard candidates.count == 1, let candidate = candidates.first else {
                throw WalletError.invalidCredential("The issuer publishes no single key for this credential.")
            }
            key = candidate
        }
        return try SDJWTVerifier.verify(
            parsed, issuerKey: key, expectedIssuer: issuer.issuer.absoluteString,
            expectedVct: configuration.vct, holderKey: holderKey, now: now())
    }
}

// MARK: - Offers between preview and issue

private struct PreparedAttestedKey: Sendable {
    let tag: String
    let signer: any HolderSigning
    let attestation: String
    let nonce: String?
    let reused: Bool
}

private enum CredentialNonceError: Error {
    case rejected
}

nonisolated struct PendingOffer: Sendable {
    let grant: ParsedOffer.Grant
    let issuer: VerifiedIssuer
    let x509ConfigurationIDs: Set<String>
    let isHAIPOffer: Bool
    /// Stored credentials whose holder keys the new credentials must reuse, indexed by configuration.
    var renewals: [String: StoredCredential] = [:]
}

private struct OAuthClientContext: Sendable {
    let dpopKey: WalletDPoPKey?
    let dpop: DPoPSession?
    let walletAttestation: WalletClientAttestation?
}

private struct AuthorizationCodeResult: Sendable {
    let code: String
    let verifier: String
    let context: OAuthClientContext
    let requestedScopes: Set<String>?
    let usedAuthorizationDetails: Bool
}

private struct TokenAuthorization: Sendable {
    let accessToken: String
    let tokenType: TokenType
    /// The key and server-scoped nonces used at the token endpoint stay in use at the Credential Endpoint.
    let dpop: DPoPSession?
    /// Present only if the token response returned authorization_details.
    let credentialIdentifiers: [String: [String]]?

    enum TokenType: Sendable {
        case bearer
        case dpop

        var authorizationScheme: String {
            switch self {
            case .bearer: "Bearer"
            case .dpop: "DPoP"
            }
        }
    }

    func identifiers(for configurationId: String) throws -> [String?] {
        guard let credentialIdentifiers else { return [nil] }
        guard let identifiers = credentialIdentifiers[configurationId] else {
            throw WalletError.invalidIssuer("The token does not authorize the selected credential.")
        }
        return identifiers.map(Optional.some)
    }
}

/// A nonce belongs to the server that issued it. In particular, the AS token nonce is never sent
/// to the Credential Issuer, even when a single issuance session uses both hosts (RFC 9449 §9).
private actor DPoPSession {
    enum Role: String, Sendable { case authorizationServer, resourceServer }
    private let key: WalletDPoPKey
    private var nonces: [String: String] = [:]

    init(key: WalletDPoPKey) { self.key = key }

    func proof(method: String, url: URL, role: Role, accessToken: String? = nil, issuedAt: Date) throws -> String {
        try key.proof(
            method: method, url: url, accessToken: accessToken,
            nonce: nonces[Self.key(for: url, role: role)], issuedAt: issuedAt)
    }

    /// Accept only a bounded RFC 6749 NQCHAR nonce. Returns false for absent or malformed headers.
    @discardableResult
    func remember(_ nonce: String?, from url: URL, role: Role) -> Bool {
        guard let nonce, !nonce.isEmpty, nonce.utf8.count <= 1_024,
              nonce.utf8.allSatisfy({ $0 == 0x21 || (0x23...0x5B).contains($0) || (0x5D...0x7E).contains($0) })
        else { return false }
        nonces[Self.key(for: url, role: role)] = nonce
        return true
    }

    private static func key(for url: URL, role: Role) -> String {
        "\(role.rawValue)|\(url.scheme?.lowercased() ?? "")://\(url.host?.lowercased() ?? ""):\(url.port ?? 443)"
    }
}

/// Verified offers waiting for the user's decision. Grant secrets stay here, out of the preview.
private actor OfferSessions {
    private var offers: [UUID: PendingOffer] = [:]
    private var order: [UUID] = []
    private var claimed: Set<UUID> = []
    private let limit = 8

    func put(_ id: UUID, _ offer: PendingOffer) {
        offers[id] = offer
        order.append(id)
        while order.count > limit { offers[order.removeFirst()] = nil }
    }

    func get(_ id: UUID) -> PendingOffer? { offers[id] }

    func claim(_ id: UUID) -> Bool {
        guard offers[id] != nil else { return false }
        return claimed.insert(id).inserted
    }

    func release(_ id: UUID) { claimed.remove(id) }

    func remove(_ id: UUID) {
        offers[id] = nil
        order.removeAll { $0 == id }
        claimed.remove(id)
    }
}

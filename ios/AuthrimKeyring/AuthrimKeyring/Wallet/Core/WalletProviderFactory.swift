import Foundation

/// The services HAIP issuance needs, built from the build's `WalletDeploymentConfig`.
nonisolated struct AuthrimHAIPServices: Sendable {
    let walletAttestation: any WalletAttestationProvider
    let keyAttestation: any KeyAttestationProvider
    let keyAttestationTrust: any KeyAttestationTrustSource
    let issuerTrust: any IssuerCertificateTrustSource
}

nonisolated enum WalletProviderFactory {
    /// Nil when the build is not configured for HAIP (no provider, roots or issuers): the wallet then
    /// runs without it, and nothing falls back to unattested requests. A malformed configuration
    /// is an error, not nil.
    static func make(
        config: WalletDeploymentConfig, isRelease: Bool, http: WalletHTTP = WalletHTTP(),
        appAttest: (any AppAttestService)? = nil, state: any AppAttestStateStore = KeychainAppAttestState()
    ) throws -> AuthrimHAIPServices? {
        guard config.providerOrigin != nil else { return nil }
        try config.requireHAIPReady(isRelease: isRelease)
        guard let origin = config.providerOrigin, let issuer = config.providerIssuer else { return nil }
        let service: any AppAttestService
        if let appAttest {
            service = appAttest
        } else {
            switch config.providerKind {
            case .appAttest: service = SystemAppAttestService()
            case .debugUnattested:
                #if DEBUG
                service = DebugUnattestedAppAttest()
                #else
                throw WalletDeploymentConfig.Problem.invalid(WalletDeploymentConfig.Key.providerKind)
                #endif
            }
        }
        let provider = AuthrimWalletProvider(
            origin: origin, issuer: issuer, roots: config.providerRoots, clientID: config.clientID,
            issuers: config.credentialIssuers, appAttest: service, state: state, http: http)
        return AuthrimHAIPServices(
            walletAttestation: provider, keyAttestation: provider,
            keyAttestationTrust: PinnedKeyAttestationTrust(
                roots: config.providerRoots, issuers: config.credentialIssuers),
            issuerTrust: AuthrimCATrustSource(roots: config.authrimRoots))
    }
}

// MARK: - Several ecosystems in one wallet (the EUDI test providers and the Authrim ones)

/// The first provider that supports the issuer answers; the others are never asked.
nonisolated struct CompositeWalletAttestationProvider: WalletAttestationProvider {
    let providers: [any WalletAttestationProvider]
    func supports(issuer: URL) -> Bool { providers.contains { $0.supports(issuer: issuer) } }
    func attestation(for clientKey: PublicJWK, issuer: URL) async throws -> WalletClientAttestation {
        guard let provider = providers.first(where: { $0.supports(issuer: issuer) }) else {
            throw WalletError.unsupportedKeyAttestation
        }
        return try await provider.attestation(for: clientKey, issuer: issuer)
    }
}

nonisolated struct CompositeKeyAttestation: KeyAttestationProvider, KeyAttestationTrustSource {
    let providers: [any KeyAttestationProvider]
    let trust: [any KeyAttestationTrustSource]
    func supports(issuer: URL) -> Bool { providers.contains { $0.supports(issuer: issuer) } }
    func attestation(for holderKey: PublicJWK, nonce: String?, issuer: URL) async throws -> String {
        guard let provider = providers.first(where: { $0.supports(issuer: issuer) }) else {
            throw WalletError.unsupportedKeyAttestation
        }
        return try await provider.attestation(for: holderKey, nonce: nonce, issuer: issuer)
    }
    /// Trust sources are tried in order; the first that knows the issuer answers, and a source that
    /// refuses passes to the next. None answering is a refusal.
    func trustedRoots(for attestation: String, issuer: URL) async throws -> [Data] {
        for source in trust {
            if let roots = try? await source.trustedRoots(for: attestation, issuer: issuer), !roots.isEmpty {
                return roots
            }
        }
        throw WalletError.unsupportedKeyAttestation
    }
}

nonisolated struct CompositeIssuerTrust: IssuerCertificateTrustSource {
    let sources: [any IssuerCertificateTrustSource]
    func supports(issuer: URL, vct: String) -> Bool { sources.contains { $0.supports(issuer: issuer, vct: vct) } }
    func prepare(issuer: URL, vct: String) async throws {
        try await first(issuer, vct)?.prepare(issuer: issuer, vct: vct)
    }
    func trustedRoots(for chainDER: [Data], issuer: URL, vct: String) async throws -> [Data] {
        guard let source = first(issuer, vct) else { throw WalletError.unsupportedIssuerCertificateTrust }
        return try await source.trustedRoots(for: chainDER, issuer: issuer, vct: vct)
    }
    private func first(_ issuer: URL, _ vct: String) -> (any IssuerCertificateTrustSource)? {
        sources.first { $0.supports(issuer: issuer, vct: vct) }
    }
}

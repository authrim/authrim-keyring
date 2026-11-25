import Foundation

/// Trust anchors for credentials signed under an Authrim issuing CA: the roots come from the build
/// configuration (`WalletDeploymentConfig.authrimRoots`), never from a credential, offer or QR code.
/// It answers only for the configured credential types, so other issuers keep their own policies.
nonisolated struct AuthrimCATrustSource: IssuerCertificateTrustSource {
    /// The administrator credential type of Authrim.
    static let adminVCT = "https://authrim.com/credentials/admin/v1"

    let roots: [Data]
    let vcts: Set<String>

    init(roots: [Data], vcts: Set<String> = [AuthrimCATrustSource.adminVCT]) {
        self.roots = roots
        self.vcts = vcts
    }

    func supports(issuer: URL, vct: String) -> Bool {
        !roots.isEmpty && vcts.contains(vct)
    }

    func trustedRoots(for chainDER: [Data], issuer: URL, vct: String) async throws -> [Data] {
        guard supports(issuer: issuer, vct: vct) else { throw WalletError.unsupportedIssuerCertificateTrust }
        return roots
    }
}

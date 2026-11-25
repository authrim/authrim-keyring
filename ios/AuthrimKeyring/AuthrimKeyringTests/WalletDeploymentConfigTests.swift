import Foundation
import Testing
@testable import AuthrimKeyring

@Suite
struct WalletDeploymentConfigTests {
    private static let root = AuthrimPKIFixture.root

    private func info(_ overrides: [String: Any] = [:]) -> [String: Any] {
        var base: [String: Any] = [
            "WalletProviderOrigin": "https://provider.example.net",
            "WalletProviderPinnedRoots": [Self.root],
            "AuthrimTrustedRoots": [Self.root],
            "WalletProviderIssuers": ["https://issuer.example.com"],
            "WalletRedirectURI": "https://keyring.example.net/oauth/callback",
        ]
        base.merge(overrides) { _, new in new }
        return base
    }

    @Test func readsValuesAndAppliesDefaults() throws {
        let config = try WalletDeploymentConfig(info: info(), allowDebugProvider: false)
        #expect(config.clientID == "keyring-ios")
        #expect(config.providerKind == .appAttest)
        #expect(config.providerIssuer == config.providerOrigin)
        #expect(config.providerRoots.count == 1 && config.authrimRoots.count == 1)
        try config.requireHAIPReady(isRelease: true)
    }

    @Test func releaseRefusesTheDebugProvider() throws {
        let overrides = ["WalletProviderKind": "debugUnattested"]
        #expect(throws: WalletDeploymentConfig.Problem.invalid("WalletProviderKind")) {
            try WalletDeploymentConfig(info: info(overrides), allowDebugProvider: false)
        }
        let debug = try WalletDeploymentConfig(info: info(overrides), allowDebugProvider: true)
        #expect(throws: WalletDeploymentConfig.Problem.invalid("WalletProviderKind")) {
            try debug.requireHAIPReady(isRelease: true)
        }
        try debug.requireHAIPReady(isRelease: false)
    }

    @Test func failsClosedWithoutProviderOrPinnedRoots() throws {
        let noProvider = try WalletDeploymentConfig(
            info: info(["WalletProviderOrigin": "$(WALLET_PROVIDER_ORIGIN)"]), allowDebugProvider: false)
        #expect(throws: WalletDeploymentConfig.Problem.missing("WalletProviderOrigin")) {
            try noProvider.requireHAIPReady(isRelease: true)
        }
        let noRoots = try WalletDeploymentConfig(info: info(["WalletProviderPinnedRoots": []]), allowDebugProvider: false)
        #expect(throws: WalletDeploymentConfig.Problem.missing("WalletProviderPinnedRoots")) {
            try noRoots.requireHAIPReady(isRelease: true)
        }
        let noAuthrim = try WalletDeploymentConfig(info: info(["AuthrimTrustedRoots": []]), allowDebugProvider: false)
        #expect(throws: WalletDeploymentConfig.Problem.missing("AuthrimTrustedRoots")) {
            try noAuthrim.requireHAIPReady(isRelease: true)
        }
    }

    @Test func rejectsMalformedValues() {
        for (key, value) in [
            ("WalletProviderOrigin", "http://provider.example.net"),
            ("WalletProviderPinnedRoots", ["not base64 der"]),
            ("AuthrimTrustedRoots", "single string"),
            ("WalletClientID", "has space"),
            ("WalletRedirectURI", "http://keyring.example.net/cb"),
        ] as [(String, Any)] {
            #expect(throws: WalletDeploymentConfig.Problem.self, Comment(rawValue: key)) {
                try WalletDeploymentConfig(info: info([key: value]), allowDebugProvider: true)
            }
        }
        #expect(throws: WalletDeploymentConfig.Problem.missing("WalletRedirectURI")) {
            try WalletDeploymentConfig(info: ["WalletRedirectURI": "$(WALLET_REDIRECT_URI)"], allowDebugProvider: true)
        }
    }

    @Test func authrimTrustSourceAnswersOnlyForItsTypesAndRoots() async throws {
        let der = try #require(Data(base64Encoded: Self.root))
        let url = try #require(URL(string: "https://issuer.example.com"))
        let source = AuthrimCATrustSource(roots: [der])
        #expect(source.supports(issuer: url, vct: AuthrimCATrustSource.adminVCT))
        #expect(!source.supports(issuer: url, vct: "urn:other"))
        #expect(!AuthrimCATrustSource(roots: []).supports(issuer: url, vct: AuthrimCATrustSource.adminVCT))
        #expect(try await source.trustedRoots(for: [], issuer: url, vct: AuthrimCATrustSource.adminVCT) == [der])
    }
}

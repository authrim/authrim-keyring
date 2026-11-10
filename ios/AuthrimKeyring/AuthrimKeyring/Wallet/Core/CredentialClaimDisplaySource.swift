import Foundation

/// A claim label selected for the wallet's language before the one-time offer is redeemed.
nonisolated struct CredentialClaimDisplaySource: Sendable, Equatable {
    let path: [SDJWTVCTypeMetadata.PathPart]
    let label: String
    let description: String?
    let direction: CredentialTextDirection
}

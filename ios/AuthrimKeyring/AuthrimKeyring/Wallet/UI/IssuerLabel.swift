import SwiftUI

/// The issuer as the user must judge it: its host first, its own name only as a claim, and how far
/// that has been confirmed.
struct IssuerLabel: View {
    let issuer: URL
    let displayName: String?
    let trust: IssuerTrust
    var displayDirection: CredentialTextDirection? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if case .verified(let name, _) = trust {
                Text(name)
                    .font(.title3.weight(.semibold))
                Text(issuer.walletHost)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .accessibilityLabel(Text("Issuer address \(issuer.walletHost)"))
            } else {
                Text(issuer.walletHost)
                    .font(.title3.weight(.semibold))
                    .textSelection(.enabled)
                    .accessibilityLabel(Text("Issuer address \(issuer.walletHost)"))
                if let displayName, !displayName.isEmpty {
                    Text("Calls itself “\((displayDirection ?? .auto).isolate(displayName))”")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }
            level
                .font(.footnote.weight(.semibold))
        }
    }

    @ViewBuilder
    private var level: some View {
        switch trust {
        case .verified(_, let anchor):
            Label("Verified by \(anchor)", systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green)
        case .confirmedByUser(let date):
            Label("Confirmed by you on \(date.formatted(date: .abbreviated, time: .omitted))", systemImage: "person.crop.circle.badge.checkmark")
                .foregroundStyle(.tint)
        case .unconfirmed:
            Label("Unverified issuer", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
        }
    }
}

#if DEBUG
#Preview {
    let issuer = URL(string: "https://id.example.com")!
    Form {
        IssuerLabel(issuer: issuer, displayName: "Example Corp", trust: .verified(name: "Example Corporation", anchor: "Example Federation"))
        IssuerLabel(issuer: issuer, displayName: "Example Corp", trust: .confirmedByUser(.now))
        IssuerLabel(issuer: issuer, displayName: "Example Corp", trust: .unconfirmed)
    }
}
#endif

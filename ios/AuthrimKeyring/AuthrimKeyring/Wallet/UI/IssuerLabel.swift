import SwiftUI

/// The issuer as the user must judge it: its host first, its own name only as a claim.
struct IssuerLabel: View {
    let issuer: URL
    let displayName: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(issuer.walletHost)
                .font(.title3.weight(.semibold))
                .textSelection(.enabled)
                .accessibilityLabel(Text("Issuer address \(issuer.walletHost)"))
            if let displayName, !displayName.isEmpty {
                Text("Calls itself “\(displayName)”")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Label("Unverified issuer", systemImage: "exclamationmark.triangle.fill")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(.orange)
        }
    }
}

#if DEBUG
#Preview {
    Form {
        IssuerLabel(issuer: URL(string: "https://id.example.com")!, displayName: "Example Corp")
    }
}
#endif

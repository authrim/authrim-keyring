import SwiftUI

/// A credential drawn as a card, large enough to hold up to someone across the table.
struct CredentialFaceView: View {
    let credential: StoredCredential
    let trust: IssuerTrust

    private let cornerRadius: CGFloat = 22
    private let appearance = CardAppearance(base: CardColor.presets[5])

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            issuer
            VStack(alignment: .leading, spacing: 4) {
                Text(credential.credentialName)
                    .font(.title2.weight(.bold))
                if let holder {
                    Text(holder)
                        .font(.title3.weight(.semibold))
                }
            }
            Spacer(minLength: 0)
            if !otherClaims.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(otherClaims, id: \.name) { claim in
                        VStack(alignment: .leading, spacing: 0) {
                            Text(claim.name)
                                .font(.caption)
                                .opacity(0.75)
                            Text(claim.value)
                                .font(.subheadline.weight(.medium))
                        }
                    }
                }
            }
            expiry
        }
        .padding(20)
        // About the shape of a card in a wallet; larger text makes it taller.
        .frame(maxWidth: .infinity, minHeight: 220, alignment: .topLeading)
        .foregroundStyle(appearance.foreground)
        .background {
            RoundedRectangle(cornerRadius: cornerRadius)
                .fill(LinearGradient(colors: [appearance.top, appearance.bottom], startPoint: .topLeading, endPoint: .bottomTrailing))
                .strokeBorder(appearance.foreground.opacity(0.15))
                .shadow(color: .black.opacity(0.18), radius: 12, y: 6)
        }
        .frame(maxWidth: 480)
        .accessibilityElement(children: .combine)
    }

    /// Who issued it: the name a trust anchor gives, otherwise the address, never the
    /// name the issuer gives itself.
    private var issuer: some View {
        HStack(spacing: 6) {
            Image(systemName: trustSymbol)
                .accessibilityLabel(trustLabel)
            if case .verified(let name, _) = trust {
                Text(name)
            } else {
                Text(credential.issuer.walletHost)
            }
        }
        .font(.subheadline.weight(.semibold))
        .opacity(0.9)
    }

    private var trustSymbol: String {
        switch trust {
        case .verified: "checkmark.seal.fill"
        case .confirmedByUser: "person.crop.circle.badge.checkmark"
        case .unconfirmed: "exclamationmark.triangle.fill"
        }
    }

    private var trustLabel: Text {
        switch trust {
        case .verified: Text("Verified issuer")
        case .confirmedByUser: Text("Issuer confirmed by you")
        case .unconfirmed: Text("Unverified issuer")
        }
    }

    /// The holder's name, which leads the card as it does on an ID card. Picked the same
    /// way each time, and left among the other claims when there are several to choose from.
    private var holderClaim: (name: String, value: String)? {
        let names = credential.sortedClaims.filter { $0.name.lowercased() == "name" }
        return names.count == 1 ? names[0] : nil
    }

    private var holder: String? { holderClaim?.value }

    /// The claims below the name; the full list is further down the screen.
    private var otherClaims: [(name: String, value: String)] {
        Array(credential.sortedClaims.filter { $0.name != holderClaim?.name }.prefix(3))
    }

    @ViewBuilder
    private var expiry: some View {
        if let expiresAt = credential.expiresAt {
            if credential.isExpired {
                Label("Expired", systemImage: "exclamationmark.circle.fill")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(appearance.warning)
            } else {
                Text("Expires \(expiresAt, format: .dateTime.year().month().day())")
                    .font(.footnote)
                    .opacity(0.85)
            }
        }
    }
}

#if DEBUG
#Preview {
    VStack {
        CredentialFaceView(credential: .previewSample, trust: .verified(name: "Example Corporation", anchor: "Example Federation"))
        CredentialFaceView(credential: .previewExpired, trust: .unconfirmed)
    }
    .padding()
}
#endif

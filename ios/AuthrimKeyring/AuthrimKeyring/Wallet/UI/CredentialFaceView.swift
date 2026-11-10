import SwiftUI

/// A credential drawn as a card, large enough to hold up to someone across the table.
struct CredentialFaceView: View {
    let credential: StoredCredential
    let trust: IssuerTrust
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.colorSchemeContrast) private var colorSchemeContrast

    private let cornerRadius: CGFloat = 22
    private let appearance = CardAppearance(base: CardColor.presets[5])

    private var foreground: Color {
        CredentialArtworkColors.foreground(for: credential, fallback: appearance.foreground)
    }

    var body: some View {
        if let variant = credential.credentialDisplay?.selectedSVGVariant(
            colorScheme: colorScheme == .dark ? "dark" : "light",
            contrast: colorSchemeContrast == .increased ? "high" : "normal") {
            templateFace(variant)
        } else {
            simpleFace
        }
    }

    private func templateFace(_ variant: CredentialSVGVariant) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            SVGArtworkView(data: variant.data, fit: .contain)
                .aspectRatio(variant.orientation == "portrait" ? 0.70 : 1.5625, contentMode: .fit)
                .background(Color.white)
                .clipShape(.rect(cornerRadius: cornerRadius))
                .overlay(RoundedRectangle(cornerRadius: cornerRadius).strokeBorder(.primary.opacity(0.15)))
                .shadow(color: .black.opacity(0.18), radius: 12, y: 6)
            HStack(spacing: 6) {
                Image(systemName: trustSymbol)
                VStack(alignment: .leading, spacing: 1) {
                    trustLabel
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    if case .verified(let name, _) = trust {
                        Text(name)
                    }
                    Text(credential.issuer.walletHost)
                }
                Spacer(minLength: 8)
                expiry
            }
            .font(.footnote.weight(.medium))
            .foregroundStyle(.primary)
        }
        .frame(maxWidth: 480)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text("\(credential.credentialName), \(credential.issuer.walletHost), \(trustLabel)"))
    }

    private var simpleFace: some View {
        VStack(alignment: .leading, spacing: 16) {
            issuer
            VStack(alignment: .leading, spacing: 4) {
                Text((credential.credentialDisplay?.nameDirection ?? .auto).isolate(credential.credentialName))
                    .font(.title2.weight(.bold))
                if let description = credential.credentialDisplay?.description {
                    Text((credential.credentialDisplay?.descriptionDirection ?? .auto).isolate(description))
                        .font(.subheadline)
                        .lineLimit(2)
                        .opacity(0.85)
                }
                if let holder {
                    Text(CredentialTextDirection.auto.isolate(holder))
                        .font(.title3.weight(.semibold))
                }
            }
            Spacer(minLength: 0)
            if !otherClaims.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(otherClaims) { claim in
                        VStack(alignment: .leading, spacing: 0) {
                            Text(claim.direction.isolate(claim.label))
                                .font(.caption)
                                .opacity(0.75)
                            Text(CredentialTextDirection.auto.isolate(claim.value))
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
        .foregroundStyle(foreground)
        .background {
            let shape = RoundedRectangle(cornerRadius: cornerRadius)
            CredentialArtworkBackground(
                credential: credential, fallbackTop: appearance.top, fallbackBottom: appearance.bottom)
                .clipShape(shape)
                .overlay(shape.strokeBorder(foreground.opacity(0.15)))
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
            VStack(alignment: .leading, spacing: 1) {
                if case .verified(let name, _) = trust {
                    Text(name)
                }
                Text(credential.issuer.walletHost)
                    .font(.caption)
            }
            Spacer(minLength: 8)
            CredentialArtworkLogo(credential: credential, size: 52)
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
    private var otherClaims: [CredentialDisplayClaim] {
        let rows = credential.credentialDisplay?.claimDisplays ?? credential.sortedClaims.map {
            CredentialDisplayClaim(id: "raw:" + $0.name, label: $0.name, value: $0.value,
                                   description: nil, direction: .auto)
        }
        guard let holderName = holderClaim?.name else { return Array(rows.prefix(3)) }
        let encoded = Base64URL.encode(Data(holderName.utf8))
        return Array(rows.filter {
            $0.id != "n" + encoded && $0.id != "raw:" + encoded && $0.id != "raw:" + holderName
        }.prefix(3))
    }

    @ViewBuilder
    private var expiry: some View {
        if let expiresAt = credential.expiresAt {
            if credential.isExpired {
                Label("Expired", systemImage: "exclamationmark.circle.fill")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(foreground)
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

import SwiftUI

/// A credential on the home screen, drawn like the other cards. Tapping opens its details.
struct CredentialCardView: View {
    let appearance: CardAppearance
    let credential: StoredCredential
    let onOpen: () -> Void
    @Environment(\.isPageSwiping) private var isPageSwiping
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.colorSchemeContrast) private var colorSchemeContrast

    private let cornerRadius: CGFloat = 18

    private var hasIssuerBackground: Bool {
        credential.credentialDisplay?.backgroundColor != nil ||
            credential.credentialDisplay?.backgroundImageData != nil
    }

    private var foreground: Color {
        CredentialArtworkColors.foreground(for: credential, fallback: appearance.foreground)
    }

    var body: some View {
        Button { if !isPageSwiping { onOpen() } } label: {
            HStack(alignment: .top, spacing: 12) {
                // No kind badge or heading: the card itself reads as a credential.
                VStack(alignment: .leading, spacing: 4) {
                    Text((credential.credentialDisplay?.nameDirection ?? .auto).isolate(credential.credentialName))
                        .font(.headline)
                    Text(credential.issuer.walletHost)
                        .font(.subheadline)
                    if let summary = credential.summary {
                        Text(summary)
                            .font(.subheadline)
                    }
                    expiry
                }
                Spacer(minLength: 8)
                VStack(alignment: .trailing, spacing: 8) {
                    if let variant = credential.credentialDisplay?.selectedSVGVariant(
                        colorScheme: colorScheme == .dark ? "dark" : "light",
                        contrast: colorSchemeContrast == .increased ? "high" : "normal") {
                        SVGArtworkView(data: variant.data, fit: .contain)
                            .frame(width: variant.orientation == "portrait" ? 34 : 72, height: 48)
                            .background(.white)
                            .clipShape(.rect(cornerRadius: 6))
                            .accessibilityHidden(true)
                    } else {
                        CredentialArtworkLogo(credential: credential, size: 44)
                    }
                    Image(systemName: "chevron.right")
                        .font(.footnote.weight(.semibold))
                        .opacity(0.8)
                        .accessibilityHidden(true)
                }
            }
            .multilineTextAlignment(.leading)
            .padding(.horizontal, 16)
            .padding(.vertical, 14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .foregroundStyle(foreground)
        .clipShape(.rect(cornerRadius: cornerRadius))
        .background {
            let shape = RoundedRectangle(cornerRadius: cornerRadius)
            if hasIssuerBackground {
                CredentialArtworkBackground(
                    credential: credential, fallbackTop: appearance.top, fallbackBottom: appearance.bottom)
                    .clipShape(shape)
                    .overlay(shape.strokeBorder(foreground.opacity(0.15)))
                    .shadow(color: .black.opacity(0.12), radius: 8, y: 4)
            } else if let opacity = appearance.glassOpacity {
                GlassCardFace(shape: shape, tint: appearance.top, opacity: opacity)
            } else {
                shape
                    .fill(LinearGradient(colors: [appearance.top, appearance.bottom], startPoint: .topLeading, endPoint: .bottomTrailing))
                    .strokeBorder(appearance.foreground.opacity(0.15))
                    .shadow(color: .black.opacity(0.12), radius: 8, y: 4)
            }
        }
        .contentShape(.contextMenuPreview, .rect(cornerRadius: cornerRadius))
        .accessibilityElement(children: .combine)
        .accessibilityHint(Text("Double-tap to show the credential."))
    }

    @ViewBuilder
    private var expiry: some View {
        if let expiresAt = credential.expiresAt {
            if credential.isExpired {
                Label("Expired", systemImage: "exclamationmark.circle.fill")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(hasIssuerBackground ? foreground : appearance.warning)
            } else {
                Text("Expires \(expiresAt, format: .dateTime.year().month().day())")
                    .font(.footnote)
                    .opacity(0.85)
            }
        }
    }
}

/// The credentials at the top of the home list. Draws nothing without credentials.
struct HomeCredentialsSection: View {
    @Environment(WalletModel.self) private var wallet
    @Environment(WallpaperStore.self) private var wallpaper
    @Environment(\.colorScheme) private var colorScheme
    let search: String

    private var visible: [StoredCredential] {
        wallet.credentials.filter { $0.matches(search: search) }
    }

    var body: some View {
        if !visible.isEmpty {
            let appearance = CardAppearance(
                base: CardColor.presets[5],
                glass: wallpaper.cardGlass(in: wallpaper.colorScheme ?? colorScheme)
            )
            LazyVStack(spacing: 12) {
                ForEach(visible) { credential in
                    CredentialCardView(appearance: appearance, credential: credential) {
                        wallet.detail = credential
                    }
                }
            }
            .padding(.bottom, 4)
        }
    }
}

#if DEBUG
#Preview {
    HomeCredentialsSection(search: "")
        .padding()
        .environment(WalletModel.preview(credentials: [.previewSample, .previewExpired]))
        .environment(WallpaperStore())
}
#endif

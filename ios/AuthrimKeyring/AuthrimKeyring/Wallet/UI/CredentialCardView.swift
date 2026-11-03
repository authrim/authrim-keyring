import SwiftUI

/// A credential on the home screen, drawn like the other cards. Tapping opens its details.
struct CredentialCardView: View {
    let appearance: CardAppearance
    let credential: StoredCredential
    let onOpen: () -> Void
    @Environment(\.isPageSwiping) private var isPageSwiping

    private let cornerRadius: CGFloat = 18

    var body: some View {
        Button { if !isPageSwiping { onOpen() } } label: {
            HStack(alignment: .top, spacing: 12) {
                // No kind badge or heading: the card itself reads as a credential.
                VStack(alignment: .leading, spacing: 4) {
                    Text(credential.credentialName)
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
                Image(systemName: "chevron.right")
                    .font(.footnote.weight(.semibold))
                    .opacity(0.8)
                    .accessibilityHidden(true)
                    .padding(.top, 4)
            }
            .multilineTextAlignment(.leading)
            .padding(.horizontal, 16)
            .padding(.vertical, 14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .foregroundStyle(appearance.foreground)
        .clipShape(.rect(cornerRadius: cornerRadius))
        .background {
            let shape = RoundedRectangle(cornerRadius: cornerRadius)
            if let opacity = appearance.glassOpacity {
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
                    .foregroundStyle(appearance.warning)
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

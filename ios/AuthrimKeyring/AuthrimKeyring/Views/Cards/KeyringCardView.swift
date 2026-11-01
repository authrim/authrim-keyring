import SwiftUI

/// Colors of a card face, with a text color picked for contrast.
struct CardAppearance: Equatable {
    var top: Color
    var bottom: Color
    /// Black text on light cards, white text on dark ones.
    var usesDarkText: Bool
    /// Accent for time-critical state; falls back to the text color when no
    /// accent is legible on this card.
    var warning: Color

    init(base: CardColor) {
        let darkText = CardColor.prefersDarkText(on: [base])
        // The gradient moves away from the text color, so the base color is the
        // lowest-contrast point under the text.
        let end = darkText ? base.lightened(by: 0.2) : base.darkened(by: 0.25)
        top = Color(base)
        bottom = Color(end)
        usesDarkText = darkText

        let accent = darkText ? CardColor(hex: 0xA3001B) : CardColor(hex: 0xFFD60A)
        let accentIsLegible = [base, end].allSatisfy { CardColor.contrast($0, accent) >= 3 }
        warning = accentIsLegible ? Color(accent) : (darkText ? .black : .white)
    }

    var foreground: Color { usesDarkText ? .black : .white }
}

extension Color {
    init(_ cardColor: CardColor) {
        self.init(.sRGB, red: cardColor.red, green: cardColor.green, blue: cardColor.blue)
    }
}

extension EnvironmentValues {
    /// The appearance of the card a view is drawn on.
    @Entry var cardAppearance = CardAppearance(base: CardColor.presets[0])
}

/// Wide, slim card used on the home screen. Tapping the header reveals `detail`.
///
/// Opening and closing happen in two steps driven by the caller: the card resizes
/// while `isExpanded` changes, and `detail` fades only while `isDetailVisible` changes.
///
/// The chrome is shared by every kind of card (one-time codes now, membership
/// cards and credentials later); each kind supplies its own detail content.
struct KeyringCardView<Detail: View>: View {
    let appearance: CardAppearance
    let title: String
    let subtitle: String?
    let kind: LocalizedStringKey
    let isExpanded: Bool
    let isDetailVisible: Bool
    let onToggle: () -> Void
    @ViewBuilder let detail: () -> Detail

    private let cornerRadius: CGFloat = 18

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button(action: onToggle) { header }
                .buttonStyle(.plain)
                .accessibilityElement(children: .combine)
                .accessibilityHint(isExpanded ? Text("Double-tap to hide the details.") : Text("Double-tap to show the details."))
                .accessibilityAddTraits(.isButton)
            if isExpanded {
                VStack(alignment: .leading, spacing: 0) {
                    Rectangle()
                        .fill(appearance.foreground.opacity(0.2))
                        .frame(height: 1)
                        .padding(.horizontal, 16)
                    detail()
                        .padding(16)
                }
                // Laid out at full size right away so the card can grow around it;
                // its visibility is animated separately.
                .opacity(isDetailVisible ? 1 : 0)
                .allowsHitTesting(isDetailVisible)
                .accessibilityHidden(!isDetailVisible)
                .transition(.identity)
            }
        }
        .foregroundStyle(appearance.foreground)
        .environment(\.cardAppearance, appearance)
        .background(
            LinearGradient(colors: [appearance.top, appearance.bottom], startPoint: .topLeading, endPoint: .bottomTrailing),
            in: .rect(cornerRadius: cornerRadius)
        )
        .overlay {
            RoundedRectangle(cornerRadius: cornerRadius)
                .strokeBorder(appearance.foreground.opacity(0.15))
        }
        .clipShape(.rect(cornerRadius: cornerRadius))
        .contentShape(.contextMenuPreview, .rect(cornerRadius: cornerRadius))
        .shadow(color: .black.opacity(0.12), radius: 8, y: 4)
    }

    private var header: some View {
        HStack(spacing: 12) {
            Monogram(text: title, outline: appearance.foreground.opacity(0.5))
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.headline)
                    .lineLimit(1)
                if let subtitle {
                    // Kept opaque: the contrast check assumes solid black or white text.
                    Text(subtitle)
                        .font(.subheadline)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 8)
            Text(kind)
                .font(.caption2.weight(.semibold))
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .overlay {
                    // Outlined rather than filled so the text sits on the card color itself.
                    Capsule().strokeBorder(appearance.foreground.opacity(0.5))
                }
            Image(systemName: "chevron.down")
                .font(.footnote.weight(.semibold))
                .rotationEffect(.degrees(isExpanded ? 180 : 0))
                .opacity(0.8)
                .accessibilityHidden(true)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 14)
        .contentShape(.rect)
    }
}

private struct Monogram: View {
    let text: String
    let outline: Color

    var body: some View {
        Text(text.first.map { String($0).uppercased() } ?? "?")
            .font(.headline)
            .frame(width: 40, height: 40)
            .overlay { Circle().strokeBorder(outline, lineWidth: 1.5) }
            .accessibilityHidden(true)
    }
}

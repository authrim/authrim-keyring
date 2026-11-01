import SwiftUI

/// Colors of a card face. Organizations will be able to supply their own later;
/// until then a palette entry is picked from the card's name.
struct CardAppearance: Equatable {
    var top: Color
    var bottom: Color

    private static let palette: [CardAppearance] = [
        CardAppearance(hex: 0x5B7FA8, 0x344E6E), // slate blue
        CardAppearance(hex: 0x2E8B8B, 0x1D5E66), // teal
        CardAppearance(hex: 0x8A5F82, 0x5C3A57), // plum
        CardAppearance(hex: 0x5F8A6B, 0x3B5E46), // moss
        CardAppearance(hex: 0xA67F3F, 0x74562A), // brass
        CardAppearance(hex: 0x5560A8, 0x363C73), // indigo
        CardAppearance(hex: 0xA8505A, 0x6E2F38), // crimson
        CardAppearance(hex: 0x5E6670, 0x3A4048), // graphite
    ]

    /// Stable across launches (unlike `hashValue`), so a card keeps its color.
    static func forName(_ name: String) -> CardAppearance {
        var hash: UInt32 = 2_166_136_261
        for byte in name.lowercased().utf8 {
            hash = (hash ^ UInt32(byte)) &* 16_777_619
        }
        return palette[Int(hash % UInt32(palette.count))]
    }

    private init(hex top: UInt32, _ bottom: UInt32) {
        self.top = Color(hex: top)
        self.bottom = Color(hex: bottom)
    }
}

private extension Color {
    init(hex: UInt32) {
        self.init(
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255
        )
    }
}

/// Wide, slim card used on the home screen. Tapping the header reveals `detail`.
///
/// The chrome is shared by every kind of card (one-time codes now, membership
/// cards and credentials later); each kind supplies its own detail content.
struct KeyringCardView<Detail: View>: View {
    let appearance: CardAppearance
    let title: String
    let subtitle: String?
    let kind: LocalizedStringKey
    let isExpanded: Bool
    let onToggle: () -> Void
    @ViewBuilder let detail: () -> Detail

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private let cornerRadius: CGFloat = 18

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button(action: onToggle) { header }
                .buttonStyle(.plain)
                .accessibilityElement(children: .combine)
                .accessibilityHint(isExpanded ? Text("Double-tap to hide the details.") : Text("Double-tap to show the details."))
                .accessibilityAddTraits(.isButton)
            if isExpanded {
                Rectangle()
                    .fill(.white.opacity(0.2))
                    .frame(height: 1)
                    .padding(.horizontal, 16)
                detail()
                    .padding(16)
                    .transition(reduceMotion ? .opacity : .opacity.combined(with: .move(edge: .top)))
            }
        }
        .foregroundStyle(.white)
        .background(
            LinearGradient(colors: [appearance.top, appearance.bottom], startPoint: .topLeading, endPoint: .bottomTrailing),
            in: .rect(cornerRadius: cornerRadius)
        )
        .overlay {
            RoundedRectangle(cornerRadius: cornerRadius)
                .strokeBorder(.white.opacity(0.15))
        }
        .clipShape(.rect(cornerRadius: cornerRadius))
        .contentShape(.contextMenuPreview, .rect(cornerRadius: cornerRadius))
        .shadow(color: .black.opacity(0.12), radius: 8, y: 4)
    }

    private var header: some View {
        HStack(spacing: 12) {
            Monogram(text: title)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.headline)
                    .lineLimit(1)
                if let subtitle {
                    Text(subtitle)
                        .font(.subheadline)
                        .opacity(0.8)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 8)
            Text(kind)
                .font(.caption2.weight(.semibold))
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(.white.opacity(0.18), in: .capsule)
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

    var body: some View {
        Text(text.first.map { String($0).uppercased() } ?? "?")
            .font(.headline)
            .frame(width: 40, height: 40)
            .background(.white.opacity(0.2), in: .circle)
            .accessibilityHidden(true)
    }
}

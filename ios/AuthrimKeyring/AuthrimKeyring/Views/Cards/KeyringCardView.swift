import SwiftUI

/// A see-through card: its color at `opacity` over frosted glass that looks
/// roughly like `backdrop`.
struct CardGlass: Equatable {
    var opacity: Double
    var backdrop: CardColor
    /// Only an outline, for a closed card that shows the wallpaper.
    var isClear = false
}

/// Colors of a card face, with a text color picked for contrast.
struct CardAppearance: Equatable {
    var top: Color
    var bottom: Color
    /// Black text on light cards, white text on dark ones.
    var usesDarkText: Bool
    /// Accent for time-critical state; falls back to the text color when no
    /// accent is legible on this card.
    var warning: Color
    /// Opacity of the color over frosted glass, or nil for a solid card.
    var glassOpacity: Double?
    /// The card is clear, so the text needs a halo to stand out from the wallpaper.
    var isClearGlass: Bool

    init(base: CardColor, glass: CardGlass? = nil) {
        // Contrast is checked against what the card looks like on screen.
        func shown(_ color: CardColor) -> CardColor {
            glass.map { $0.backdrop.mixed(toward: color, by: $0.opacity) } ?? color
        }
        let darkText = CardColor.prefersDarkText(on: [shown(base)])
        // The gradient moves away from the text color, so the base color is the
        // lowest-contrast point under the text.
        let end = darkText ? base.lightened(by: 0.2) : base.darkened(by: 0.25)
        top = Color(base)
        bottom = Color(end)
        usesDarkText = darkText
        glassOpacity = glass?.opacity
        isClearGlass = glass?.isClear ?? false

        let accent = darkText ? CardColor(hex: 0xA3001B) : CardColor(hex: 0xFFD60A)
        let accentIsLegible = [shown(base), shown(end)].allSatisfy { CardColor.contrast($0, accent) >= 3 }
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
    /// The SF Symbol that stands for `kind` on the monogram.
    let kindSymbol: String
    var isFavorite = false
    let isExpanded: Bool
    let isDetailVisible: Bool
    let onToggle: () -> Void
    @ViewBuilder let detail: () -> Detail

    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @Environment(\.isPageSwiping) private var isPageSwiping

    private let cornerRadius: CGFloat = 18

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button { if !isPageSwiping { onToggle() } } label: { header }
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
        // Switched at once rather than animated, so it is not redrawn while the card resizes.
        .animation(nil) { content in
            content.shadow(color: appearance.isClearGlass ? halo : .clear, radius: appearance.isClearGlass ? 2 : 0)
        }
        .environment(\.cardAppearance, appearance)
        .clipShape(.rect(cornerRadius: cornerRadius))
        .background {
            // The shadow is cast by the card shape alone, not by the text on it, so it
            // stays cheap to redraw while the card resizes.
            let shape = RoundedRectangle(cornerRadius: cornerRadius)
            if let opacity = appearance.glassOpacity {
                // No shadow: it would show through the glass.
                GlassCardFace(shape: shape, tint: appearance.top, opacity: opacity, isClear: appearance.isClearGlass)
            } else {
                shape
                    .fill(LinearGradient(colors: [appearance.top, appearance.bottom], startPoint: .topLeading, endPoint: .bottomTrailing))
                    .strokeBorder(appearance.foreground.opacity(0.15))
                    .shadow(color: .black.opacity(0.12), radius: 8, y: 4)
            }
        }
        .contentShape(.contextMenuPreview, .rect(cornerRadius: cornerRadius))
    }

    /// The opposite of the text color, around the text on clear glass.
    private var halo: Color {
        (appearance.usesDarkText ? Color.white : .black).opacity(0.7)
    }

    @ViewBuilder
    private var header: some View {
        Group {
            if dynamicTypeSize.isAccessibilitySize {
                // Too large for one row: the names wrap and the badge moves under them.
                HStack(alignment: .top, spacing: 12) {
                    VStack(alignment: .leading, spacing: 6) {
                        names(lineLimit: nil)
                        badge
                    }
                    Spacer(minLength: 8)
                    chevron
                }
            } else {
                HStack(spacing: 12) {
                    // The kind is a small mark on the monogram, so the names get the width.
                    Monogram(text: title, outline: appearance.foreground.opacity(0.5), symbol: kindSymbol)
                        .accessibilityLabel(Text(kind))
                    names(lineLimit: 1)
                    Spacer(minLength: 8)
                    chevron
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 14)
        .contentShape(.rect)
    }

    private func names(lineLimit: Int?) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 4) {
                Text(title)
                    .font(.headline)
                    .lineLimit(lineLimit)
                if isFavorite {
                    Image(systemName: "star.fill")
                        .font(.caption)
                        .accessibilityLabel("Favorite")
                }
            }
            if let subtitle {
                // Kept opaque: the contrast check assumes solid black or white text.
                Text(subtitle)
                    .font(.subheadline)
                    .lineLimit(lineLimit)
            }
        }
    }

    private var badge: some View {
        Text(kind)
            .font(.caption2.weight(.semibold))
            // On a narrow card the title gives way instead.
            .lineLimit(1)
            .fixedSize()
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .overlay {
                // Outlined rather than filled so the text sits on the card color itself.
                Capsule().strokeBorder(appearance.foreground.opacity(0.5))
            }
    }

    private var chevron: some View {
        Image(systemName: "chevron.down")
            .font(.footnote.weight(.semibold))
            .rotationEffect(.degrees(isExpanded ? 180 : 0))
            .opacity(0.8)
            .accessibilityHidden(true)
    }
}

/// A see-through card face: Liquid Glass from iOS 26, frosted material before it.
struct GlassCardFace<S: InsettableShape>: View {
    let shape: S
    let tint: Color
    /// How strongly the card color tints the glass.
    let opacity: Double
    /// Only an outline over the wallpaper: no glass and no color.
    var isClear = false

    var body: some View {
        if isClear {
            shape.strokeBorder(.white.opacity(0.35))
        } else if #available(iOS 26, *) {
            Color.clear
                .glassEffect(.regular.tint(tint.opacity(opacity)), in: shape)
        } else {
            shape
                .fill(.ultraThinMaterial)
                .overlay { shape.fill(tint).opacity(opacity) }
                .overlay { shape.strokeBorder(.white.opacity(0.2)) }
        }
    }
}

/// The first letter in a circle, with the kind of card as a symbol at its lower corner.
private struct Monogram: View {
    let text: String
    let outline: Color
    let symbol: String
    /// Grows with the letter inside it.
    @ScaledMetric(relativeTo: .headline) private var diameter: CGFloat = 40
    @ScaledMetric(relativeTo: .headline) private var markSize: CGFloat = 22

    var body: some View {
        Text(text.first.map { String($0).uppercased() } ?? "?")
            .font(.headline)
            .frame(width: diameter, height: diameter)
            .overlay {
                // Broken where the symbol sits, which then stands on the card itself.
                Circle().strokeBorder(outline, lineWidth: 1.5)
                    .mask {
                        Rectangle()
                            .overlay(alignment: .bottomTrailing) { mark { Circle().blendMode(.destinationOut) } }
                            .compositingGroup()
                    }
            }
            .overlay(alignment: .bottomTrailing) {
                mark { Image(systemName: symbol).font(.system(size: markSize * 0.72, weight: .regular)) }
            }
    }

    /// Places `content` over the lower corner of the circle.
    private func mark(@ViewBuilder _ content: () -> some View) -> some View {
        content()
            .frame(width: markSize, height: markSize)
            .offset(x: markSize * 0.25, y: markSize * 0.25)
    }
}

import SwiftUI
import UIKit

/// Form section for choosing a card's color: automatic, a preset or any custom color.
struct CardColorSection: View {
    /// nil means the automatic color.
    @Binding var selection: CardColor?
    let automatic: CardColor

    private var current: CardColor { selection ?? automatic }

    /// VoiceOver names, in the order of `CardColor.presets`.
    private static let presetNames: [LocalizedStringKey] = [
        "Slate Blue", "Teal", "Plum", "Moss", "Brass", "Indigo", "Crimson",
        "Graphite", "Black", "White", "Yellow", "Mint", "Sky", "Pink",
    ]

    var body: some View {
        Section {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 44), spacing: 4)], spacing: 4) {
                swatch(for: automatic, isSelected: selection == nil, label: Text("Automatic")) {
                    selection = nil
                }
                .overlay {
                    Image(systemName: "wand.and.stars")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(CardAppearance(base: automatic).foreground)
                        .opacity(selection == nil ? 0 : 1)
                        .allowsHitTesting(false)
                }
                ForEach(Array(zip(CardColor.presets, Self.presetNames)), id: \.0) { color, name in
                    swatch(for: color, isSelected: selection == color, label: Text(name)) {
                        selection = color
                    }
                }
            }
            .padding(.vertical, 4)

            ColorPicker("Custom Color", selection: customBinding, supportsOpacity: false)
        } header: {
            Text("Card Color")
        } footer: {
            Text("Text on the card switches between black and white to stay readable.")
        }
    }

    private func swatch(for color: CardColor, isSelected: Bool, label: Text, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Circle()
                .fill(Color(color))
                .frame(width: 36, height: 36)
                .overlay {
                    Circle().strokeBorder(Color.primary.opacity(0.15))
                }
                .overlay {
                    if isSelected {
                        Image(systemName: "checkmark")
                            .font(.caption.weight(.bold))
                            .foregroundStyle(CardAppearance(base: color).foreground)
                    }
                }
                .frame(width: 44, height: 44)
                .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .accessibilityLabel(label)
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }

    private var customBinding: Binding<Color> {
        Binding(
            get: { Color(current) },
            set: { selection = CardColor($0) }
        )
    }
}

extension CardColor {
    /// Converts a picked color to sRGB components; wide-gamut values are clamped.
    init(_ color: Color) {
        var red: CGFloat = 0, green: CGFloat = 0, blue: CGFloat = 0, alpha: CGFloat = 0
        let srgb = UIColor(color).cgColor.converted(
            to: CGColorSpace(name: CGColorSpace.sRGB)!, intent: .defaultIntent, options: nil
        )
        if let components = srgb?.components, components.count >= 3 {
            red = components[0]
            green = components[1]
            blue = components[2]
        } else {
            UIColor(color).getRed(&red, green: &green, blue: &blue, alpha: &alpha)
        }
        self.init(red: Double(red), green: Double(green), blue: Double(blue))
    }
}

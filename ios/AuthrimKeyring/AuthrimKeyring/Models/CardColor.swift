import Foundation

/// An opaque sRGB color chosen for a card face, stored with the account.
struct CardColor: Codable, Hashable, Sendable {
    var red: Double
    var green: Double
    var blue: Double

    init(red: Double, green: Double, blue: Double) {
        self.red = Self.clamp(red)
        self.green = Self.clamp(green)
        self.blue = Self.clamp(blue)
    }

    init(hex: UInt32) {
        self.init(
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255
        )
    }

    /// Colors offered as one-tap choices. The first eight are also used automatically
    /// and are dark enough for white text to meet WCAG AA (4.5:1).
    static let presets: [CardColor] = [
        CardColor(hex: 0x56779E), // slate blue
        CardColor(hex: 0x2A8080), // teal
        CardColor(hex: 0x8A5F82), // plum
        CardColor(hex: 0x567E61), // moss
        CardColor(hex: 0x906E37), // brass
        CardColor(hex: 0x5560A8), // indigo
        CardColor(hex: 0xA8505A), // crimson
        CardColor(hex: 0x5E6670), // graphite
        CardColor(hex: 0x1C1C1E), // black
        CardColor(hex: 0xF2F2F7), // white
        CardColor(hex: 0xF4D35E), // yellow
        CardColor(hex: 0x9ED8C6), // mint
        CardColor(hex: 0xA9CBEF), // sky
        CardColor(hex: 0xF2B5C4), // pink
    ]

    /// A stable color derived from a name, used until the user picks one.
    static func automatic(for name: String) -> CardColor {
        // FNV-1a: stable across launches, unlike `hashValue`.
        var hash: UInt32 = 2_166_136_261
        for byte in name.lowercased().utf8 {
            hash = (hash ^ UInt32(byte)) &* 16_777_619
        }
        return presets[Int(hash % 8)]
    }

    /// Mixes the color toward black by `amount` (0...1).
    func darkened(by amount: Double) -> CardColor {
        CardColor(red: red * (1 - amount), green: green * (1 - amount), blue: blue * (1 - amount))
    }

    /// Mixes the color toward white by `amount` (0...1).
    func lightened(by amount: Double) -> CardColor {
        CardColor(red: red + (1 - red) * amount, green: green + (1 - green) * amount, blue: blue + (1 - blue) * amount)
    }

    /// WCAG 2.x relative luminance.
    var relativeLuminance: Double {
        func linear(_ value: Double) -> Double {
            value <= 0.040_45 ? value / 12.92 : pow((value + 0.055) / 1.055, 2.4)
        }
        return 0.2126 * linear(red) + 0.7152 * linear(green) + 0.0722 * linear(blue)
    }

    /// WCAG contrast ratio between two colors (1...21).
    static func contrast(_ first: CardColor, _ second: CardColor) -> Double {
        let lighter = max(first.relativeLuminance, second.relativeLuminance)
        let darker = min(first.relativeLuminance, second.relativeLuminance)
        return (lighter + 0.05) / (darker + 0.05)
    }

    static let white = CardColor(red: 1, green: 1, blue: 1)
    static let black = CardColor(red: 0, green: 0, blue: 0)

    /// Whether black text reads better than white on every one of `backgrounds`.
    static func prefersDarkText(on backgrounds: [CardColor]) -> Bool {
        let darkContrast = backgrounds.map { contrast($0, .black) }.min() ?? 0
        let lightContrast = backgrounds.map { contrast($0, .white) }.min() ?? 0
        return darkContrast > lightContrast
    }

    private static func clamp(_ value: Double) -> Double {
        value.isFinite ? min(max(value, 0), 1) : 0
    }
}

import SwiftUI

/// What is shown behind the cards on the home screen.
nonisolated struct WallpaperSettings: Codable, Equatable, Sendable {
    enum Kind: Codable, Equatable, Sendable {
        /// The system background, following light and dark mode.
        case system
        case preset(String)
        case photo
    }

    /// Mountains with glass cards, until the user chooses otherwise.
    var kind: Kind = .preset("mountains")
    /// Blur of a photo, 0...1. Slightly blurred by default so cards stand out.
    var blur: Double = 0.15
    /// Darkening over a photo, 0...1.
    var dim: Double = 0.2
    /// Average gamma-encoded luma (sRGB, 0...1) of the photo, measured when it was chosen.
    var photoLightness: Double = 0.5
    /// Cards let the wallpaper show through, like frosted glass.
    var glassCards = true
    /// How much of the wallpaper shows through a glass card.
    var cardTransparency = 0.75
    /// Closed glass cards are almost clear, so the wallpaper shows; a card is
    /// frosted only while it is open.
    var clearUntilOpened = false

    static let maximumBlurRadius: CGFloat = 30
    static let maximumDim = 0.7
    static let cardTransparencyRange = 0.1...0.9

    init() {}

    // Settings saved by an earlier version may lack the newer keys.
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let defaults = WallpaperSettings()
        kind = try container.decodeIfPresent(Kind.self, forKey: .kind) ?? defaults.kind
        blur = try container.decodeIfPresent(Double.self, forKey: .blur) ?? defaults.blur
        dim = try container.decodeIfPresent(Double.self, forKey: .dim) ?? defaults.dim
        photoLightness = try container.decodeIfPresent(Double.self, forKey: .photoLightness) ?? defaults.photoLightness
        glassCards = try container.decodeIfPresent(Bool.self, forKey: .glassCards) ?? defaults.glassCards
        cardTransparency = try container.decodeIfPresent(Double.self, forKey: .cardTransparency) ?? defaults.cardTransparency
        clearUntilOpened = try container.decodeIfPresent(Bool.self, forKey: .clearUntilOpened) ?? defaults.clearUntilOpened
    }
}

nonisolated struct WallpaperPreset: Identifiable, Sendable {
    enum Style: Sendable {
        case gradient(top: UInt32, bottom: UInt32)
        /// A picture from the asset catalog, in a tall, a square, and a thumbnail version,
        /// with its average gamma-encoded luma.
        case image(lightness: Double)
    }

    let id: String
    let name: LocalizedStringResource
    let style: Style
    /// Whether text on top of it should be light.
    let isDark: Bool

    static let all: [WallpaperPreset] = [
        WallpaperPreset(id: "nebula", name: "Nebula", style: .image(lightness: 0.2), isDark: true),
        WallpaperPreset(id: "mountains", name: "Mountains", style: .image(lightness: 0.2), isDark: true),
        WallpaperPreset(id: "watercolor", name: "Watercolor", style: .image(lightness: 0.86), isDark: false),
        WallpaperPreset(id: "mist", name: "Mist", style: .gradient(top: 0xE8EEF5, bottom: 0xCBD6E2), isDark: false),
        WallpaperPreset(id: "dawn", name: "Dawn", style: .gradient(top: 0xFBE3D6, bottom: 0xE4D4F2), isDark: false),
        WallpaperPreset(id: "sand", name: "Sand", style: .gradient(top: 0xF3EBDD, bottom: 0xE2D3BB), isDark: false),
        WallpaperPreset(id: "mint", name: "Mint", style: .gradient(top: 0xDDF2EA, bottom: 0xBFE0D6), isDark: false),
        WallpaperPreset(id: "ocean", name: "Ocean", style: .gradient(top: 0x1F4E6B, bottom: 0x0E2236), isDark: true),
        WallpaperPreset(id: "forest", name: "Forest", style: .gradient(top: 0x2F5640, bottom: 0x142A1E), isDark: true),
        WallpaperPreset(id: "dusk", name: "Dusk", style: .gradient(top: 0x4B3B6E, bottom: 0x1C1530), isDark: true),
        WallpaperPreset(id: "night", name: "Night", style: .gradient(top: 0x22252C, bottom: 0x0B0C0F), isDark: true),
    ]

    static func named(_ id: String) -> WallpaperPreset? {
        all.first { $0.id == id }
    }

    /// Average gamma-encoded luma (sRGB, 0...1).
    var lightness: Double {
        switch style {
        case .gradient(let top, let bottom):
            (CardColor(hex: top).luma + CardColor(hex: bottom).luma) / 2
        case .image(let lightness):
            lightness
        }
    }

    /// The asset for an image preset: the thumbnail, or the version closest in shape to `size`.
    func imageName(for size: CGSize, thumbnail: Bool) -> String {
        guard !thumbnail else { return "Wallpaper-\(id)-thumb" }
        // The tall pictures are about 0.46 wide per unit of height; 0.68 is halfway
        // between that and a square, so each screen gets the smaller crop.
        let isTall = size.height > 0 && size.width / size.height < 0.68
        return "Wallpaper-\(id)-\(isTall ? "tall" : "square")"
    }
}

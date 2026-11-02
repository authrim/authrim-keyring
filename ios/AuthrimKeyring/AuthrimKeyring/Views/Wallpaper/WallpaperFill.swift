import SwiftUI

/// Draws the home screen wallpaper to fill its frame.
struct WallpaperFill: View {
    @Environment(WallpaperStore.self) private var wallpaper

    var body: some View {
        switch wallpaper.settings.kind {
        case .system:
            Color(.systemGroupedBackground)
        case .preset(let id):
            if let preset = WallpaperPreset.named(id) {
                WallpaperPresetFill(preset: preset)
            } else {
                Color(.systemGroupedBackground)
            }
        case .photo:
            if let photo = wallpaper.photo {
                Color.clear
                    .overlay {
                        Image(uiImage: photo)
                            .resizable()
                            .scaledToFill()
                            .blur(radius: wallpaper.settings.blur * WallpaperSettings.maximumBlurRadius, opaque: true)
                    }
                    .overlay(Color.black.opacity(wallpaper.settings.dim))
                    .clipped()
            } else {
                Color(.systemGroupedBackground)
            }
        }
    }
}

/// Draws a preset wallpaper to fill its frame.
struct WallpaperPresetFill: View {
    let preset: WallpaperPreset
    var thumbnail = false

    var body: some View {
        switch preset.style {
        case .gradient(let top, let bottom):
            LinearGradient(
                colors: [Color(CardColor(hex: top)), Color(CardColor(hex: bottom))],
                startPoint: .top,
                endPoint: .bottom
            )
        case .image:
            GeometryReader { proxy in
                Image(preset.imageName(for: proxy.size, thumbnail: thumbnail))
                    .resizable()
                    .scaledToFill()
                    .frame(width: proxy.size.width, height: proxy.size.height)
                    .clipped()
            }
            .accessibilityHidden(true)
        }
    }
}

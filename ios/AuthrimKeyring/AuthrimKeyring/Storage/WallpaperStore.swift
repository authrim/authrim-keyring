import Foundation
import ImageIO
import Observation
import SwiftUI
import UIKit

/// The home screen wallpaper. A chosen photo is kept as a file on this device
/// only; it is not part of iCloud sync or Keyring backups.
@Observable
final class WallpaperStore {
    private static let settingsKey = "wallpaper"
    private static let maximumPhotoPixels = 2400

    private(set) var settings: WallpaperSettings
    private(set) var photo: UIImage?
    /// Bumped by every new choice, so a photo still being prepared cannot
    /// replace a wallpaper picked after it.
    private var choice = 0

    private let defaults: UserDefaults
    private let photoURL: URL?

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        photoURL = try? FileManager.default
            .url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
            .appending(path: "Wallpaper.jpg")
        let saved = defaults.data(forKey: Self.settingsKey)
            .flatMap { try? JSONDecoder().decode(WallpaperSettings.self, from: $0) }
        settings = saved ?? WallpaperSettings()
        if settings.kind == .photo {
            photo = photoURL.flatMap { UIImage(contentsOfFile: $0.path(percentEncoded: false)) }
            if photo == nil { settings.kind = WallpaperSettings().kind }
        } else {
            // A photo left behind by an earlier choice is no longer shown.
            removePhotoFile()
        }
    }

    /// Light or dark text for the wallpaper, or nil to follow the system.
    var colorScheme: ColorScheme? {
        switch settings.kind {
        case .system:
            return nil
        case .preset(let id):
            return WallpaperPreset.named(id).map { $0.isDark ? .dark : .light }
        case .photo:
            // The dimming overlay scales the encoded components, so dim first and
            // then linearize; 0.179 is where black and white text have equal contrast.
            let shown = settings.photoLightness * (1 - settings.dim)
            let luminance = shown <= 0.040_45 ? shown / 12.92 : pow((shown + 0.055) / 1.055, 2.4)
            return luminance < 0.179 ? .dark : .light
        }
    }

    /// How cards are drawn over the wallpaper, or nil for solid cards.
    /// - Parameter colorScheme: The appearance the home screen is drawn in.
    func cardGlass(in colorScheme: ColorScheme) -> CardGlass? {
        guard settings.glassCards else { return nil }
        let wallpaperLightness: Double = switch settings.kind {
        case .system: colorScheme == .dark ? 0 : 0.95
        case .preset(let id): WallpaperPreset.named(id)?.lightness ?? 0.5
        case .photo: settings.photoLightness * (1 - settings.dim)
        }
        // The frosted glass pulls the wallpaper toward white or black.
        let wallpaperColor = CardColor(red: wallpaperLightness, green: wallpaperLightness, blue: wallpaperLightness)
        let backdrop = wallpaperColor.mixed(toward: colorScheme == .dark ? .black : .white, by: 0.4)
        return CardGlass(opacity: 1 - settings.cardTransparency, backdrop: backdrop)
    }

    func select(_ kind: WallpaperSettings.Kind) {
        guard kind != .photo else { return }
        choice += 1
        settings.kind = kind
        removePhotoFile()
        save()
    }

    func setBlur(_ blur: Double) {
        settings.blur = min(max(blur, 0), 1)
        save()
    }

    func setDim(_ dim: Double) {
        settings.dim = min(max(dim, 0), WallpaperSettings.maximumDim)
        save()
    }

    func setGlassCards(_ isOn: Bool) {
        settings.glassCards = isOn
        save()
    }

    func setCardTransparency(_ transparency: Double) {
        let range = WallpaperSettings.cardTransparencyRange
        settings.cardTransparency = min(max(transparency, range.lowerBound), range.upperBound)
        save()
    }

    /// Starts choosing a photo. Pass the result to `setPhoto(_:choice:)`, so a photo
    /// that is still loading cannot replace a wallpaper picked after it.
    func beginPhotoChoice() -> Int {
        choice += 1
        return choice
    }

    /// Makes `imageData` the wallpaper. Returns false only when it is not a usable
    /// image; a photo overtaken by a newer choice is dropped without an error.
    func setPhoto(_ imageData: Data, choice request: Int) async -> Bool {
        guard request == choice else { return true }
        guard var photoURL else { return false }
        let maximumPixels = Self.maximumPhotoPixels
        let prepared = await Task.detached(priority: .userInitiated) {
            Self.prepare(imageData, maximumPixels: maximumPixels)
        }.value
        guard let prepared else { return false }
        guard request == choice else { return true }
        do {
            // Only readable while the device is unlocked, like the rest of the app's data.
            try prepared.jpeg.write(to: photoURL, options: [.atomic, .completeFileProtection])
            // Stays on this device: not in iCloud or computer backups either.
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try photoURL.setResourceValues(values)
        } catch {
            return false
        }
        photo = UIImage(data: prepared.jpeg)
        settings.kind = .photo
        settings.photoLightness = prepared.lightness
        save()
        return true
    }

    private func save() {
        if let data = try? JSONEncoder().encode(settings) {
            defaults.set(data, forKey: Self.settingsKey)
        }
    }

    private func removePhotoFile() {
        photo = nil
        if let photoURL {
            try? FileManager.default.removeItem(at: photoURL)
        }
    }

    /// Downscales and re-encodes the photo, which also drops its metadata such as location.
    nonisolated private static func prepare(_ data: Data, maximumPixels: Int) -> (jpeg: Data, lightness: Double)? {
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
              let image = CGImageSourceCreateThumbnailAtIndex(source, 0, [
                  kCGImageSourceCreateThumbnailFromImageAlways: true,
                  kCGImageSourceCreateThumbnailWithTransform: true,
                  kCGImageSourceThumbnailMaxPixelSize: maximumPixels,
              ] as CFDictionary),
              let jpeg = UIImage(cgImage: image).jpegData(compressionQuality: 0.85)
        else { return nil }
        return (jpeg, averageLightness(of: image))
    }

    /// Average gamma-encoded luma, so dimming can be applied before linearizing.
    /// Measures the middle of the photo, the part a tall screen shows.
    nonisolated private static func averageLightness(of fullImage: CGImage) -> Double {
        let tallScreen = 0.46
        let width = Double(fullImage.width), height = Double(fullImage.height)
        let shown = width / height > tallScreen
            ? CGRect(x: (width - height * tallScreen) / 2, y: 0, width: height * tallScreen, height: height)
            : CGRect(x: 0, y: (height - width / tallScreen) / 2, width: width, height: width / tallScreen)
        let image = fullImage.cropping(to: shown.integral) ?? fullImage
        // A small sample is enough to tell a light photo from a dark one.
        let side = 16
        var pixels = [UInt8](repeating: 0, count: side * side * 4)
        guard let space = CGColorSpace(name: CGColorSpace.sRGB),
              let context = CGContext(
                  data: &pixels, width: side, height: side, bitsPerComponent: 8, bytesPerRow: side * 4,
                  space: space, bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue
              )
        else { return 0.5 }
        context.interpolationQuality = .medium
        context.draw(image, in: CGRect(x: 0, y: 0, width: side, height: side))
        let total = stride(from: 0, to: pixels.count, by: 4).reduce(0.0) { sum, index in
            sum + (0.2126 * Double(pixels[index]) + 0.7152 * Double(pixels[index + 1]) + 0.0722 * Double(pixels[index + 2])) / 255
        }
        return total / Double(side * side)
    }
}

import ImageIO
import SwiftUI

/// Presentation of the issuer's bounded raster artwork snapshot. The card never dereferences a
/// URL while it is on screen; image bytes were checked and saved during issuance.
struct CredentialArtworkBackground: View {
    let credential: StoredCredential
    let fallbackTop: Color
    let fallbackBottom: Color

    var body: some View {
        GeometryReader { geometry in
            ZStack {
                if let color = CredentialArtworkColors.color(credential.credentialDisplay?.backgroundColor) {
                    color
                } else {
                    LinearGradient(colors: [fallbackTop, fallbackBottom],
                                   startPoint: .topLeading, endPoint: .bottomTrailing)
                }
                if credential.credentialDisplay?.backgroundImageMediaType == "image/svg+xml",
                   let data = credential.credentialDisplay?.backgroundImageData {
                    SVGArtworkView(data: data, fit: .cover)
                        .frame(width: geometry.size.width, height: geometry.size.height)
                    imageOverlay
                } else if let image = CredentialArtworkImage.cgImage(credential.credentialDisplay?.backgroundImageData) {
                    Image(decorative: image, scale: 1)
                        .resizable()
                        .scaledToFill()
                        .frame(width: geometry.size.width, height: geometry.size.height)
                        .clipped()
                    imageOverlay
                }
            }
            .frame(width: geometry.size.width, height: geometry.size.height)
        }
        .accessibilityHidden(true)
    }

    private var imageOverlay: LinearGradient {
        LinearGradient(
            colors: [.black.opacity(0.72), .black.opacity(0.58), .black.opacity(0.72)],
            startPoint: .top, endPoint: .bottom)
    }
}

struct CredentialArtworkLogo: View {
    let credential: StoredCredential
    let size: CGFloat

    var body: some View {
        if credential.credentialDisplay?.logoMediaType == "image/svg+xml",
           let data = credential.credentialDisplay?.logoData {
            SVGArtworkView(data: data, fit: .contain)
                .frame(width: size, height: size)
                .accessibilityElement()
                .accessibilityLabel(credential.credentialDisplay?.logoAltText ?? "")
                .accessibilityHidden(credential.credentialDisplay?.logoAltText == nil)
        } else if let image = CredentialArtworkImage.cgImage(credential.credentialDisplay?.logoData) {
            Image(image, scale: 1, label: Text(credential.credentialDisplay?.logoAltText ?? ""))
                .resizable()
                .scaledToFit()
                .frame(width: size, height: size)
                .accessibilityLabel(credential.credentialDisplay?.logoAltText ?? "")
                .accessibilityHidden(credential.credentialDisplay?.logoAltText == nil)
        }
    }
}

private enum CredentialArtworkImage {
    private final class CachedImage: NSObject {
        let image: CGImage
        init(_ image: CGImage) { self.image = image }
    }

    private static let cache: NSCache<NSData, CachedImage> = {
        let cache = NSCache<NSData, CachedImage>()
        cache.totalCostLimit = 32 * 1024 * 1024
        return cache
    }()

    static func cgImage(_ data: Data?) -> CGImage? {
        guard let data else { return nil }
        let key = data as NSData
        if let cached = cache.object(forKey: key) { return cached.image }
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
              let cgImage = CGImageSourceCreateImageAtIndex(source, 0, nil) else { return nil }
        cache.setObject(CachedImage(cgImage), forKey: key,
                        cost: cgImage.width * cgImage.height * 4)
        return cgImage
    }
}

enum CredentialArtworkColors {
    static func color(_ hex: String?) -> Color? {
        guard let channels = channels(hex) else { return nil }
        return Color(red: Double(channels.0) / 255, green: Double(channels.1) / 255,
                     blue: Double(channels.2) / 255)
    }

    static func foreground(for credential: StoredCredential, fallback: Color) -> Color {
        let display = credential.credentialDisplay
        if display?.backgroundImageData != nil { return .white }
        guard let background = channels(display?.backgroundColor) else { return fallback }
        if let preferred = channels(display?.textColor), contrast(preferred, background) >= 4.5 {
            return color(display?.textColor) ?? fallback
        }
        let white: (UInt8, UInt8, UInt8) = (255, 255, 255)
        let black: (UInt8, UInt8, UInt8) = (0, 0, 0)
        return contrast(white, background) >= contrast(black, background) ? .white : .black
    }

    private static func channels(_ hex: String?) -> (UInt8, UInt8, UInt8)? {
        guard let hex, hex.count == 7, hex.first == "#" else { return nil }
        let bytes = Array(hex.utf8)
        guard let red = UInt8(String(decoding: bytes[1...2], as: UTF8.self), radix: 16),
              let green = UInt8(String(decoding: bytes[3...4], as: UTF8.self), radix: 16),
              let blue = UInt8(String(decoding: bytes[5...6], as: UTF8.self), radix: 16) else { return nil }
        return (red, green, blue)
    }

    private static func contrast(
        _ a: (UInt8, UInt8, UInt8), _ b: (UInt8, UInt8, UInt8)
    ) -> Double {
        let brighter = max(luminance(a), luminance(b))
        let darker = min(luminance(a), luminance(b))
        return (brighter + 0.05) / (darker + 0.05)
    }

    private static func luminance(_ rgb: (UInt8, UInt8, UInt8)) -> Double {
        func linear(_ byte: UInt8) -> Double {
            let value = Double(byte) / 255
            return value <= 0.04045 ? value / 12.92 : pow((value + 0.055) / 1.055, 2.4)
        }
        return 0.2126 * linear(rgb.0) + 0.7152 * linear(rgb.1) + 0.0722 * linear(rgb.2)
    }
}

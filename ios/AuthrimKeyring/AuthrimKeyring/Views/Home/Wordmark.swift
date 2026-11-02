import CoreText
import SwiftUI

/// "AUTHRIM KEYRING" in Cinzel, spaced like the Authrim logo on authrim.com.
///
/// A logo, so it grows with the text size only up to `maximumTypeSize` and is
/// never cut off; VoiceOver reads it, and the bar shows "Keyring" once scrolled.
struct Wordmark: View {
    static let maximumTypeSize = DynamicTypeSize.xxxLarge

    @ScaledMetric(relativeTo: .title) private var size: CGFloat = 24

    var body: some View {
        Text(verbatim: "AUTHRIM KEYRING")
            .font(.custom(Self.fontName, fixedSize: size))
            // The logo's letter spacing: 0.28 of the type size.
            .tracking(size * 0.28)
            .lineLimit(1)
            .minimumScaleFactor(0.6)
            .fixedSize(horizontal: false, vertical: true)
            // Where the large title sits: the full width, from the leading edge.
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 14)
            .padding(.bottom, 6)
            .accessibilityLabel(Text(verbatim: "Authrim Keyring"))
            .accessibilityAddTraits(.isHeader)
    }

    private static let fontName = "Cinzel-SemiBold"

    /// Registers the bundled Cinzel, licensed under the SIL Open Font License
    /// (`Fonts/Cinzel-OFL.txt`). Call once before the wordmark is shown.
    static func registerFont() {
        guard let url = Bundle.main.url(forResource: fontName, withExtension: "ttf") else { return }
        // Already registered is fine; anything else falls back to the system font.
        CTFontManagerRegisterFontsForURL(url as CFURL, .process, nil)
    }
}

import CoreText
import SwiftUI

/// "AUTHRIM Keyring" in Cinzel, spaced like the Authrim logo on authrim.com. Cinzel
/// has no lowercase letters: "Keyring" shows as small capitals after a capital K.
///
/// A logo, so it grows with the text size only up to `maximumTypeSize` and is
/// never cut off; VoiceOver reads it as "Authrim Keyring".
struct Wordmark: View {
    enum Style {
        /// The home screen's title, from the leading edge.
        case title
        /// Centered on screens with little else on them, such as the lock screen. It
        /// keeps the one size the launch screen shows it at, so launching continues
        /// into it unchanged.
        case logo
        /// "Keyring" in the navigation bar, once the title has scrolled under it.
        case bar
    }

    static let maximumTypeSize = DynamicTypeSize.xxxLarge

    var style = Style.title
    @ScaledMetric(relativeTo: .title) private var titleSize: CGFloat = 18
    @ScaledMetric(relativeTo: .headline) private var barSize: CGFloat = 17

    private var size: CGFloat {
        switch style {
        case .title: titleSize
        case .logo: 24
        case .bar: barSize
        }
    }

    var body: some View {
        // The logo's letter spacing: 0.28 of the type size.
        let tracking = size * 0.28
        let isCentered = style != .title
        Text(verbatim: style == .bar ? "Keyring" : "AUTHRIM Keyring")
            .font(.custom(Self.fontName, fixedSize: size))
            .tracking(tracking)
            // Tracking also follows the last letter; matching space before the first
            // keeps a centered wordmark in the middle.
            .padding(.leading, isCentered ? tracking : 0)
            .lineLimit(1)
            .minimumScaleFactor(0.6)
            .fixedSize(horizontal: style == .bar, vertical: true)
            .frame(maxWidth: style == .bar ? nil : .infinity, alignment: isCentered ? .center : .leading)
            .accessibilityLabel(style == .bar ? Text(verbatim: "Keyring") : Text(verbatim: "Authrim Keyring"))
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

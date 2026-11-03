import SwiftUI

/// A key confirmation code such as `ABCD-EFGH`, set large so it can be compared with the console.
struct ConfirmationCodeText: View {
    let code: String
    var font = Font.system(.largeTitle, design: .monospaced, weight: .semibold)

    var body: some View {
        Text(code)
            .font(font)
            .minimumScaleFactor(0.5)
            .lineLimit(1)
            .textSelection(.enabled)
            // VoiceOver reads the letters one by one instead of trying to say a word.
            .speechSpellsOutCharacters()
            .accessibilityLabel(Text("Confirmation code"))
            .accessibilityValue(Text(code))
    }
}

#if DEBUG
#Preview {
    ConfirmationCodeText(code: "ABCD-EFGH")
}
#endif

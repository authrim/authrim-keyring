import SwiftUI

/// Detail content of a counter-based card. Each code works once, so one is only
/// made when asked for; it stays shown until the card closes.
struct HOTPCodePanel: View {
    let account: OTPAccount
    var recoveryCodesLeft: Int?
    let isCopied: Bool
    let onCopy: (String) -> Void

    @Environment(AccountStore.self) private var store
    @State private var code: String?
    @ScaledMetric(relativeTo: .largeTitle) private var codeSize: CGFloat = 34

    var body: some View {
        if let code {
            Button { onCopy(code) } label: {
                HStack(alignment: .center, spacing: 12) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(TOTPGenerator.formatted(code))
                            .font(.system(size: codeSize, weight: .semibold, design: .monospaced))
                            .minimumScaleFactor(0.6)
                            .lineLimit(1)
                        Text(isCopied ? "Copied" : "Tap the code to copy")
                            .font(.caption)
                        RecoveryCodesLeftLabel(count: recoveryCodesLeft)
                    }
                    Spacer(minLength: 8)
                    if isCopied {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.title2)
                            .transition(.scale.combined(with: .opacity))
                    }
                }
                .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .animation(.default, value: isCopied)
            .sensoryFeedback(.success, trigger: isCopied) { _, new in new }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text("Code \(code.map(String.init).joined(separator: " "))"))
            .accessibilityValue(isCopied ? Text("Copied") : Text(verbatim: ""))
            .accessibilityHint("Double-tap to copy the code.")
            .accessibilityAddTraits(.isButton)
        } else {
            VStack(alignment: .leading, spacing: 6) {
                Button("Show Next Code", systemImage: "arrow.forward.circle") {
                    code = store.nextCode(for: account.id)
                }
                .font(.headline)
                .buttonStyle(.plain)
                Text("Each code works once. Show the next one when the service asks for it.")
                    .font(.caption)
                RecoveryCodesLeftLabel(count: recoveryCodesLeft)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

import SwiftUI

struct AccountRowView: View {
    let account: OTPAccount
    let now: Date
    let isCopied: Bool
    let onCopy: () -> Void

    var body: some View {
        let code = TOTPGenerator.code(for: account, at: now)
        let remaining = code.secondsRemaining(at: now)

        Button(action: onCopy) {
            HStack(alignment: .center, spacing: 12) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(account.displayTitle)
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.primary)
                        .lineLimit(1)
                    if let subtitle = account.displaySubtitle {
                        Text(subtitle)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                    Text(TOTPGenerator.formatted(code.value))
                        .font(.system(.largeTitle, design: .monospaced, weight: .medium))
                        .foregroundStyle(remaining <= 5 ? Color.red : Color.accentColor)
                        .contentTransition(.numericText())
                        .minimumScaleFactor(0.6)
                        .lineLimit(1)
                }
                Spacer(minLength: 8)
                if isCopied {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.title2)
                        .foregroundStyle(.green)
                        .transition(.scale.combined(with: .opacity))
                } else {
                    CountdownRing(remaining: remaining, period: TimeInterval(account.period))
                }
            }
            .padding(.vertical, 4)
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
        .animation(.default, value: isCopied)
        .animation(.default, value: code.value)
        .sensoryFeedback(.success, trigger: isCopied) { _, new in new }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(accessibilityText(code: code.value, remaining: remaining))
        .accessibilityValue(isCopied ? Text("Copied") : Text(""))
        .accessibilityHint("Double-tap to copy the code.")
        .accessibilityAddTraits(.isButton)
    }

    private func accessibilityText(code: String, remaining: TimeInterval) -> String {
        let spokenCode = code.map(String.init).joined(separator: " ")
        let seconds = Int(remaining.rounded(.up))
        let name = [account.displayTitle, account.displaySubtitle].compactMap { $0 }.joined(separator: ", ")
        return String(localized: "\(name), code \(spokenCode), \(seconds) seconds left")
    }
}

struct CountdownRing: View {
    let remaining: TimeInterval
    let period: TimeInterval

    var body: some View {
        let fraction = period > 0 ? remaining / period : 0
        ZStack {
            Circle()
                .stroke(Color.secondary.opacity(0.2), lineWidth: 3)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(remaining <= 5 ? Color.red : Color.accentColor, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 1), value: fraction)
            Text("\(Int(remaining.rounded(.up)))")
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
        }
        .frame(width: 32, height: 32)
        .accessibilityHidden(true)
    }
}

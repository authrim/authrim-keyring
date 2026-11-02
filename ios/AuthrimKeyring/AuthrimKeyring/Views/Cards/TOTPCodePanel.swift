import SwiftUI

/// Detail content of a one-time code card: the current code and its countdown, or
/// for a counter-based account the next code on request.
struct TOTPCodePanel: View {
    let account: OTPAccount
    /// Unused recovery codes kept for this card, or nil when it has none.
    var recoveryCodesLeft: Int?
    let isCopied: Bool
    /// Copies the code shown.
    let onCopy: (String) -> Void

    @ScaledMetric(relativeTo: .largeTitle) private var codeSize: CGFloat = 34

    var body: some View {
        if account.kind.isTimeBased {
            timeBased
        } else {
            HOTPCodePanel(account: account, recoveryCodesLeft: recoveryCodesLeft, isCopied: isCopied, onCopy: onCopy)
        }
    }

    private var timeBased: some View {
        // Only expanded cards tick, so collapsed cards cost nothing.
        TimelineView(.periodic(from: .now, by: 1)) { timeline in
            let code = TOTPGenerator.code(for: account, at: timeline.date)
                ?? TOTPGenerator.Code(value: "", validFrom: timeline.date, validUntil: timeline.date)
            let remaining = code.secondsRemaining(at: timeline.date)

            Button { onCopy(code.value) } label: {
                HStack(alignment: .center, spacing: 12) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(TOTPGenerator.formatted(code.value))
                            .font(.system(size: codeSize, weight: .semibold, design: .monospaced))
                            .contentTransition(.numericText())
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
                    } else {
                        CountdownRing(remaining: remaining, period: TimeInterval(account.period))
                    }
                }
                .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .animation(.default, value: code.value)
            .animation(.default, value: isCopied)
            .sensoryFeedback(.success, trigger: isCopied) { _, new in new }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(accessibilityText(code: code.value, remaining: remaining))
            .accessibilityValue(isCopied ? Text("Copied") : Text(verbatim: ""))
            .accessibilityHint("Double-tap to copy the code.")
            .accessibilityAddTraits(.isButton)
        }
    }

    private func accessibilityText(code: String, remaining: TimeInterval) -> String {
        let spokenCode = code.map(String.init).joined(separator: " ")
        let seconds = Int(remaining.rounded(.up))
        return String(localized: "Code \(spokenCode), \(seconds) seconds left")
    }
}

/// How many unused recovery codes a card has, when it has any.
struct RecoveryCodesLeftLabel: View {
    let count: Int?

    var body: some View {
        if let count {
            Label("Recovery codes: \(count) left", systemImage: "key.viewfinder")
                .font(.caption2)
                .opacity(0.8)
        }
    }
}

struct CountdownRing: View {
    let remaining: TimeInterval
    let period: TimeInterval

    @Environment(\.cardAppearance) private var appearance

    private var isExpiring: Bool { remaining <= 5 }

    var body: some View {
        let fraction = period > 0 ? remaining / period : 0
        ZStack {
            Circle()
                .stroke(appearance.foreground.opacity(0.25), lineWidth: 3)
            Circle()
                .trim(from: 0, to: fraction)
                .stroke(isExpiring ? appearance.warning : appearance.foreground, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.linear(duration: 1), value: fraction)
            Text("\(Int(remaining.rounded(.up)))")
                .font(.caption.monospacedDigit().weight(.semibold))
        }
        .frame(width: 36, height: 36)
        .accessibilityHidden(true)
    }
}

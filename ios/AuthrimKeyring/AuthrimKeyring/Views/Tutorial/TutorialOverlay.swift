import SwiftUI

/// Dims the screen except for one control and explains it in a callout,
/// one step at a time.
struct TutorialOverlay: View {
    let steps: [TutorialStep]
    /// Returns a target's frame in window coordinates; nil centers the callout.
    let frame: (TutorialTarget) -> CGRect?
    @Binding var index: Int
    let onFinish: () -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize
    @AccessibilityFocusState private var isTitleFocused: Bool
    /// Bumped once UIKit has laid out again, so target frames are read afresh.
    @State private var layoutPass = 0

    private let arrowSize = CGSize(width: 22, height: 11)
    private let margin: CGFloat = 16
    private let maxCalloutWidth: CGFloat = 560

    private var step: TutorialStep { steps[index] }
    private var isLast: Bool { index == steps.count - 1 }

    var body: some View {
        ZStack {
            GeometryReader { proxy in
                SpotlightShape(hole: spot(in: proxy) ?? .zero)
                    .fill(.black.opacity(0.55), style: FillStyle(eoFill: true))
                    // Swallows taps so the screen underneath stays still.
                    .contentShape(.rect)
                    .onTapGesture {}
                    .accessibilityHidden(true)
            }
            .ignoresSafeArea()

            // Inside the safe area, so the callout never sits under the notch or home bar.
            GeometryReader { proxy in
                callout(pointingAt: spot(in: proxy), in: proxy.size)
                    .onChange(of: proxy.size) { remeasure() }
            }
        }
        .onAppear {
            remeasure()
            isTitleFocused = true
        }
        .onChange(of: dynamicTypeSize) { remeasure() }
        .onChange(of: index) { isTitleFocused = true }
    }

    /// The target in this reader's coordinates, or nil when it is not on screen.
    private func spot(in proxy: GeometryProxy) -> CGRect? {
        _ = layoutPass
        guard let target = frame(step.target) else { return nil }
        let origin = proxy.frame(in: .global).origin
        let local = target.offsetBy(dx: -origin.x, dy: -origin.y).insetBy(dx: -6, dy: -6)
        // Generous on every side: the callout area excludes the safe area, where bar
        // buttons may sit (above, or down the side as on an iPhone Duo), yet still
        // points at them.
        let visible = CGRect(origin: .zero, size: proxy.size).insetBy(dx: -80, dy: -80)
        return visible.contains(CGPoint(x: local.midX, y: local.midY)) ? local : nil
    }

    /// UIKit may still be moving things when SwiftUI reports a change.
    private func remeasure() {
        Task {
            try? await Task.sleep(for: .seconds(0.35))
            layoutPass += 1
        }
    }

    @ViewBuilder
    private func callout(pointingAt spot: CGRect?, in size: CGSize) -> some View {
        let isBelow = spot.map { $0.midY < size.height / 2 } ?? true
        let calloutWidth = min(size.width, maxCalloutWidth)
        // Under the target where the screen is wider than the callout, as when the
        // toolbar runs down the side of a closed iPhone Duo; centered otherwise.
        let centerX = spot.map {
            min(max($0.midX, calloutWidth / 2), size.width - calloutWidth / 2)
        } ?? size.width / 2
        let cardMinX = centerX - calloutWidth / 2 + margin
        let cardWidth = calloutWidth - margin * 2
        let arrowX = spot.map {
            min(max($0.midX - cardMinX - arrowSize.width / 2, 20), cardWidth - arrowSize.width - 20)
        }

        VStack(spacing: 0) {
            if isBelow, let arrowX {
                arrow(pointingUp: true, x: arrowX)
            }
            card
            if !isBelow, let arrowX {
                arrow(pointingUp: false, x: arrowX)
            }
        }
        .padding(.horizontal, margin)
        .frame(maxWidth: maxCalloutWidth)
        .offset(x: centerX - size.width / 2)
        .frame(
            maxWidth: .infinity,
            maxHeight: .infinity,
            alignment: spot == nil ? .center : (isBelow ? .top : .bottom)
        )
        .padding(.top, isBelow ? max((spot?.maxY ?? 0) + 4, 0) : 0)
        .padding(.bottom, isBelow ? 0 : max(size.height - (spot?.minY ?? size.height) + 4, 0))
        .animation(reduceMotion ? nil : .smooth(duration: 0.3), value: index)
    }

    private var card: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text(step.title)
                    .font(.headline)
                    .accessibilityAddTraits(.isHeader)
                    .accessibilityFocused($isTitleFocused)
                Spacer(minLength: 8)
                if !isLast {
                    Button("Skip", action: onFinish)
                        .font(.subheadline)
                }
            }
            // Scrolls only when large text would push the buttons off screen.
            ViewThatFits(in: .vertical) {
                message
                ScrollView { message }
                    .scrollBounceBehavior(.basedOnSize)
            }
            HStack(spacing: 12) {
                Text("\(index + 1) of \(steps.count)")
                    .font(.subheadline.weight(.semibold))
                    .monospacedDigit()
                Spacer(minLength: 8)
                if index > 0 {
                    Button("Previous") { move(by: -1) }
                        .buttonStyle(.bordered)
                }
                Button(isLast ? "Done" : "Next") {
                    if isLast { onFinish() } else { move(by: 1) }
                }
                .buttonStyle(.borderedProminent)
            }
            .padding(.top, 4)
        }
        .padding(20)
        .background(Color(.tertiarySystemBackground), in: .rect(cornerRadius: 20))
        .shadow(color: .black.opacity(0.2), radius: 12, y: 4)
        .accessibilityElement(children: .contain)
        .accessibilityAddTraits(.isModal)
        .accessibilityAction(.escape, onFinish)
    }

    private var message: some View {
        Text(step.message)
            .font(.subheadline)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func arrow(pointingUp: Bool, x: CGFloat) -> some View {
        Triangle()
            .fill(Color(.tertiarySystemBackground))
            .frame(width: arrowSize.width, height: arrowSize.height)
            .rotationEffect(.degrees(pointingUp ? 0 : 180))
            .offset(x: x)
            .frame(maxWidth: .infinity, alignment: .leading)
            // `x` is measured from the physical left edge, also in right-to-left languages.
            .environment(\.layoutDirection, .leftToRight)
            .accessibilityHidden(true)
    }

    private func move(by delta: Int) {
        withAnimation(reduceMotion ? nil : .smooth(duration: 0.3)) {
            index = min(max(index + delta, 0), steps.count - 1)
        }
    }
}

/// A full-screen rectangle with a rounded hole, filled with the even-odd rule.
private struct SpotlightShape: Shape {
    var hole: CGRect

    var animatableData: AnimatablePair<AnimatablePair<CGFloat, CGFloat>, AnimatablePair<CGFloat, CGFloat>> {
        get { .init(.init(hole.minX, hole.minY), .init(hole.width, hole.height)) }
        set { hole = CGRect(x: newValue.first.first, y: newValue.first.second, width: newValue.second.first, height: newValue.second.second) }
    }

    func path(in rect: CGRect) -> Path {
        var path = Path(rect)
        if !hole.isEmpty {
            let radius = min(18, hole.height / 2)
            path.addRoundedRect(in: hole, cornerSize: CGSize(width: radius, height: radius), style: .continuous)
        }
        return path
    }
}

private struct Triangle: Shape {
    func path(in rect: CGRect) -> Path {
        Path { path in
            path.move(to: CGPoint(x: rect.midX, y: rect.minY))
            path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY))
            path.addLine(to: CGPoint(x: rect.minX, y: rect.maxY))
            path.closeSubpath()
        }
    }
}

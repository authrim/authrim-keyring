import SwiftUI

/// The pages swiping moves between, with the one on screen marked. Tapping a name opens it,
/// which is also how VoiceOver and Switch Control reach the other pages.
struct HomePageBar: View {
    let pages: [HomePage]
    let current: HomePage
    let onSelect: (HomePage) -> Void
    @Namespace private var marker
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        HStack(spacing: 2) {
            ForEach(pages) { page in
                let isCurrent = page == current
                Button { onSelect(page) } label: {
                    Text(page.title)
                        .font(.subheadline.weight(isCurrent ? .semibold : .regular))
                        .lineLimit(1)
                        .padding(.horizontal, 14)
                        .padding(.vertical, 7)
                        .background {
                            // Slides to the new page along with the cards, unless motion is reduced.
                            if isCurrent && reduceMotion {
                                Capsule().fill(.fill)
                            } else if isCurrent {
                                Capsule().fill(.fill).matchedGeometryEffect(id: "current", in: marker)
                            }
                        }
                        .contentShape(.capsule)
                }
                .buttonStyle(.plain)
                .opacity(isCurrent ? 1 : 0.7)
                .accessibilityAddTraits(isCurrent ? .isSelected : [])
                .accessibilityShowsLargeContentViewer()
            }
        }
        .padding(4)
        .pageBarBackground()
        // Kept to one row, as a tab bar is; touching and holding a name shows it larger.
        .dynamicTypeSize(...DynamicTypeSize.xxxLarge)
    }
}

extension View {
    /// Puts `bar` above the bottom bar. From iOS 26 it is a bar of its own, so the cards
    /// fade out beneath it as they do beneath the bottom bar.
    @ViewBuilder
    func pageBar(@ViewBuilder _ bar: () -> some View) -> some View {
        if #available(iOS 26, *) {
            safeAreaBar(edge: .bottom, content: bar)
        } else {
            safeAreaInset(edge: .bottom, content: bar)
        }
    }
}

extension View {
    /// Fades the scrolling cards out as they near the bars at the bottom, which then
    /// stand on the wallpaper alone. Above, the cards run on under the status bar. The
    /// list ends one fade further down, so its last card can come fully into view.
    func fadingAboveBottomBars() -> some View {
        let fade: CGFloat = 56
        return contentMargins(.bottom, fade, for: .scrollContent)
            .mask {
                VStack(spacing: 0) {
                    Color.black
                    LinearGradient(colors: [.black, .clear], startPoint: .top, endPoint: .bottom)
                        .frame(height: fade)
                }
                .ignoresSafeArea(edges: .top)
            }
    }
}

private extension View {
    /// Liquid Glass from iOS 26, frosted material before it, so the names stay legible over the cards.
    @ViewBuilder
    func pageBarBackground() -> some View {
        if #available(iOS 26, *) {
            glassEffect(.regular, in: .capsule)
        } else {
            background(.regularMaterial, in: .capsule)
        }
    }
}

extension View {
    /// Mostly sideways drags only, so vertical scrolling stays with the scroll view.
    /// `onDrag` gets how far the finger has moved toward the trailing side; `onEnd` gets +1 to turn to
    /// the page after, -1 to the page before, or 0 to stay, as when a drag is too short,
    /// turns into scrolling, or is cancelled.
    func onPageSwipe(isEnabled: Bool, onDrag: @escaping (CGFloat) -> Void, onEnd: @escaping (Int) -> Void) -> some View {
        modifier(PageSwipe(isEnabled: isEnabled, onDrag: onDrag, onEnd: onEnd))
    }
}

private struct PageSwipe: ViewModifier {
    let isEnabled: Bool
    let onDrag: (CGFloat) -> Void
    let onEnd: (Int) -> Void
    /// Decided at the start of each drag, which is told apart by where it started:
    /// sideways, or left to the scroll view.
    @State private var direction: (start: CGPoint, isSideways: Bool)?
    /// Goes back to false however the drag stops, including when the system cancels it.
    @GestureState private var isDragging = false
    /// The finger has moved sideways further than a tap's wobble.
    @GestureState private var isMoving = false
    /// Taps on the cards are ignored while this is on: a finger lifted at the end of a
    /// swipe would otherwise open the card it ends on. Stays on a moment after the drag
    /// stops, as the card's tap and the drag's end come with the same lift of the finger.
    @State private var holdsTaps = false
    @Environment(\.layoutDirection) private var layoutDirection

    /// A drag's sideways distance toward the trailing side. The finger moves on the screen,
    /// while offsets follow the layout, which is mirrored when it runs right to left.
    private func trailingward(_ width: CGFloat) -> CGFloat {
        layoutDirection == .rightToLeft ? -width : width
    }

    func body(content: Content) -> some View {
        content
            .environment(\.isPageSwiping, holdsTaps)
            .simultaneousGesture(
                DragGesture(minimumDistance: 10).updating($isMoving) { value, isMoving, _ in
                    // An upright drag scrolls, and the scroll view already cancels taps for it.
                    if abs(value.translation.width) >= abs(value.translation.height) { isMoving = true }
                },
                isEnabled: isEnabled
            )
            .simultaneousGesture(
            DragGesture(minimumDistance: 24)
                .updating($isDragging) { _, isDragging, _ in isDragging = true }
                .onChanged { value in
                    if direction?.start != value.startLocation {
                        direction = (value.startLocation, abs(value.translation.width) > abs(value.translation.height) * 1.5)
                    }
                    if direction?.isSideways == true {
                        onDrag(trailingward(value.translation.width))
                    }
                }
                .onEnded { value in
                    guard direction?.start == value.startLocation, direction?.isSideways == true else { return }
                    // A quick flick turns the page too, though the finger moved only a little.
                    let across = trailingward(abs(value.predictedEndTranslation.width) > abs(value.translation.width)
                        ? value.predictedEndTranslation.width
                        : value.translation.width)
                    // A drag that turned into scrolling does not turn the page.
                    let isStillSideways = abs(value.translation.width) > abs(value.translation.height) * 1.5
                    // Toward the leading side brings in the page after, as the pages lie in the bar.
                    onEnd(abs(across) > 80 && isStillSideways ? (across < 0 ? 1 : -1) : 0)
                },
            isEnabled: isEnabled
        )
        .onChange(of: isDragging) { _, isDragging in
            if !isDragging { onEnd(0) }
        }
        .task(id: isMoving) {
            if isMoving {
                holdsTaps = true
            } else if holdsTaps {
                try? await Task.sleep(for: .seconds(0.15))
                // Unless a new drag cancelled the wait.
                if !Task.isCancelled { holdsTaps = false }
            }
        }
        // Searching turns the swipe off, perhaps in the middle of one.
        .onChange(of: isEnabled) { _, _ in
            direction = nil
            onEnd(0)
        }
    }
}

extension EnvironmentValues {
    /// A finger is swiping across the cards, so a tap they get is part of the swipe.
    @Entry var isPageSwiping = false
}

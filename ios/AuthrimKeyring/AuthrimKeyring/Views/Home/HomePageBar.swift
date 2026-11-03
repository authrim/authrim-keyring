import SwiftUI

/// The pages swiping moves between, with the one on screen marked. Tapping a name opens it,
/// which is also how VoiceOver and Switch Control reach the other pages.
struct HomePageBar: View {
    let pages: [HomePage]
    let current: HomePage
    let onSelect: (HomePage) -> Void

    var body: some View {
        HStack(spacing: 4) {
            ForEach(pages) { page in
                let isCurrent = page == current
                Button { onSelect(page) } label: {
                    Text(page.title)
                        .font(.subheadline.weight(isCurrent ? .semibold : .regular))
                        .padding(.horizontal, 12)
                        .padding(.vertical, 6)
                        .background {
                            if isCurrent { Capsule().fill(.regularMaterial) }
                        }
                        .contentShape(.capsule)
                }
                .buttonStyle(.plain)
                .opacity(isCurrent ? 1 : 0.7)
                .accessibilityAddTraits(isCurrent ? .isSelected : [])
            }
            Spacer(minLength: 0)
        }
    }
}

extension View {
    /// Calls `action` with +1 for a swipe toward the next page and -1 toward the previous one.
    /// Mostly sideways movement only, so vertical scrolling stays with the scroll view.
    func onPageSwipe(isEnabled: Bool, _ action: @escaping (Int) -> Void) -> some View {
        modifier(PageSwipe(isEnabled: isEnabled, action: action))
    }
}

private struct PageSwipe: ViewModifier {
    let isEnabled: Bool
    let action: (Int) -> Void
    @Environment(\.layoutDirection) private var layoutDirection

    func body(content: Content) -> some View {
        content.simultaneousGesture(
            DragGesture(minimumDistance: 24).onEnded { value in
                let across = value.translation.width
                guard abs(across) > 60, abs(across) > abs(value.translation.height) * 1.5 else { return }
                // A leftward swipe brings in the next page, unless the layout runs right to left.
                let isLeftward = across < 0
                action(isLeftward == (layoutDirection == .leftToRight) ? 1 : -1)
            },
            isEnabled: isEnabled
        )
    }
}

import SwiftUI

/// How the home list is scrolled, as far as the title above the cards cares.
/// Only the title reads `pull`, so pulling redraws the title alone.
@Observable
final class HomeTitleScroll {
    /// How far the list is pulled down past its top.
    var pull: CGFloat = 0
    /// How far the list is scrolled from its top, negative when pulled. Not observed:
    /// it changes on every frame of a scroll. Always 0 before iOS 18.
    @ObservationIgnored private(set) var offset: CGFloat = 0

    func update(offset: CGFloat) {
        self.offset = offset
        let pull = max(0, -offset)
        if pull != self.pull { self.pull = pull }
    }
}

/// The wordmark above the cards. It scrolls away with them, but stays in place when
/// the list is pulled down.
struct HomeTitle: View {
    var scroll: HomeTitleScroll
    /// Marks the cards as made up.
    var isDemo = false

    var body: some View {
        Wordmark()
            .dynamicTypeSize(...Wordmark.maximumTypeSize)
            .overlay(alignment: .trailing) {
                if isDemo {
                    Text("Demo")
                        .font(.caption.weight(.semibold))
                        .padding(.horizontal, 10)
                        .padding(.vertical, 4)
                        .overlay { Capsule().strokeBorder(.secondary) }
                }
            }
            .padding(.horizontal)
            .padding(.top, 6)
            .padding(.bottom, 4)
            .offset(y: -scroll.pull)
    }
}

extension View {
    /// Keeps `scroll` up to date with this scroll view. Before iOS 18 the offset is
    /// not available: the title then moves with a pull.
    @ViewBuilder
    func trackingHomeTitle(_ scroll: HomeTitleScroll) -> some View {
        if #available(iOS 18, *) {
            onScrollGeometryChange(for: CGFloat.self) { geometry in
                geometry.contentOffset.y + geometry.contentInsets.top
            } action: { _, offset in
                scroll.update(offset: offset)
            }
        } else {
            self
        }
    }

    /// Hides the bar along the top where the bottom bar holds the search field (iOS 26).
    /// Before that the search field is in the top bar, which therefore stays.
    @ViewBuilder
    func hidingTopBar() -> some View {
        if #available(iOS 26, *) {
            toolbar(.hidden, for: .navigationBar)
        } else {
            self
        }
    }
}

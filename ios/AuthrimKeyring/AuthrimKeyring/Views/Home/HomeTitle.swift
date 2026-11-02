import SwiftUI

/// How the home list is scrolled, as far as the title above the cards cares.
/// Only the title reads `pull`, so pulling redraws the title alone.
@Observable
final class HomeTitleScroll {
    /// How far the list is pulled down past its top.
    var pull: CGFloat = 0
    /// Whether the title has scrolled up under the navigation bar.
    var isUnderBar = false
    @ObservationIgnored var titleHeight: CGFloat = 0 {
        didSet { update(offset: offset) }
    }
    @ObservationIgnored private var offset: CGFloat = 0

    /// `offset`: how far the list is scrolled from its top, negative when pulled.
    func update(offset: CGFloat) {
        self.offset = offset
        let pull = max(0, -offset)
        if pull != self.pull { self.pull = pull }
        let isUnderBar = titleHeight > 0 && offset > titleHeight
        if isUnderBar != self.isUnderBar {
            withAnimation(.easeOut(duration: 0.15)) { self.isUnderBar = isUnderBar }
        }
    }
}

/// The wordmark above the cards. It scrolls away with them, after which the bar
/// shows "Keyring", but stays in place when the list is pulled down.
struct HomeTitle: View {
    var scroll: HomeTitleScroll

    var body: some View {
        Wordmark()
            .dynamicTypeSize(...Wordmark.maximumTypeSize)
            .padding(.horizontal)
            .padding(.top, 6)
            .padding(.bottom, 4)
            .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { scroll.titleHeight = $0 }
            .offset(y: -scroll.pull)
    }
}

extension View {
    /// Keeps `scroll` up to date with this scroll view. Before iOS 18 the offset is
    /// not available: the title then moves with a pull, and the bar keeps no title.
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
}

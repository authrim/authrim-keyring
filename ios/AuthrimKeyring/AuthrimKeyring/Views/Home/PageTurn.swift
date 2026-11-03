import SwiftUI

/// Where the home pages are while one is dragged or turned. The page next in line sits
/// beside the one on screen and follows it in, as the pages of a book do.
@MainActor
@Observable
final class PageTurn {
    /// The page beside the one on screen, and on which side.
    struct Neighbor: Equatable {
        let page: HomePage
        /// After the page on screen, on its trailing side.
        let isAfter: Bool
        /// How far down the neighbor is drawn, so its top is in view when the list
        /// is scrolled down.
        let lift: CGFloat
    }

    /// How far the page on screen has moved sideways.
    private(set) var offset: CGFloat = 0
    private(set) var neighbor: Neighbor?
    /// A page is sliding into place; drags and other turns wait for it.
    private(set) var isTurning = false
    /// The width of a page, which the neighbor sits beside.
    var width: CGFloat = 0

    /// Follows the finger, bringing in the page before or after `page` depending on the direction.
    func drag(_ across: CGFloat, from page: HomePage, in paging: HomePaging, lift: CGFloat) {
        guard !isTurning else { return }
        offset = across
        guard across != 0 else {
            neighbor = nil
            return
        }
        let isAfter = across < 0
        let page = paging.page(from: page, by: isAfter ? 1 : -1)
        if neighbor?.page != page || neighbor?.isAfter != isAfter {
            // Measured as the drag starts, so it holds still while the finger moves.
            neighbor = Neighbor(page: page, isAfter: isAfter, lift: neighbor?.lift ?? lift)
        }
    }

    /// Puts a page dragged too little back in place.
    func springBack() {
        guard !isTurning, offset != 0 else { return }
        withAnimation(.smooth(duration: 0.25)) {
            offset = 0
        } completion: { [weak self] in
            // Unless another drag has started meanwhile.
            guard let self, !self.isTurning, self.offset == 0 else { return }
            self.neighbor = nil
        }
    }

    /// Slides `page` in from its side, then calls `commit` with the neighbor's lift to
    /// make it the page on screen. A turn already under way finishes first.
    func turn(to page: HomePage, isAfter: Bool, lift: CGFloat, commit: @escaping (CGFloat) -> Void) {
        guard !isTurning else { return }
        guard width > 0 else {
            commit(0)
            return
        }
        // A neighbor already beside the page keeps its place; a new one slides in from its edge.
        let neighbor = self.neighbor.map { $0.page == page && $0.isAfter == isAfter ? $0 : nil } ?? nil
        let arriving = neighbor ?? Neighbor(page: page, isAfter: isAfter, lift: lift)
        withAnimation(.smooth(duration: 0.3)) {
            isTurning = true
            self.neighbor = arriving
            offset = isAfter ? -width : width
        } completion: { [weak self] in
            // The neighbor is exactly where the page on screen goes, so swapping them shows no jump.
            var transaction = Transaction()
            transaction.disablesAnimations = true
            withTransaction(transaction) {
                commit(arriving.lift)
                self?.reset()
            }
        }
    }

    /// Back to just the page on screen, at rest.
    func reset() {
        offset = 0
        neighbor = nil
        isTurning = false
    }

    /// Where the neighbor is drawn across.
    var neighborOffset: CGFloat {
        guard let neighbor else { return 0 }
        return offset + (neighbor.isAfter ? width : -width)
    }

    /// The page the page bar marks: the one arriving once a turn has started.
    func markedPage(_ page: HomePage) -> HomePage {
        isTurning ? neighbor?.page ?? page : page
    }
}

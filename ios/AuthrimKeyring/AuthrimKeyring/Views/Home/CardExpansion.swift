import SwiftUI

/// Which home card is open. `requestedID` is the card the user wants open; `expandedID`
/// (sized open) and `revealedID` (details shown) catch up with it one animated step at a time.
@MainActor
@Observable
final class CardExpansion {
    private(set) var requestedID: UUID?
    private(set) var expandedID: UUID?
    private(set) var revealedID: UUID?
    private var isTransitioning = false

    func toggle(_ id: UUID, reduceMotion: Bool) {
        requestedID = requestedID == id ? nil : id
        guard !isTransitioning else { return }
        Task { await settle(reduceMotion: reduceMotion) }
    }

    /// Closes every card at once, without animation.
    func closeAll() {
        requestedID = nil
        expandedID = nil
        revealedID = nil
    }

    /// Moves the cards toward `requestedID`, one step at a time: details fade out, the
    /// card resizes, and details fade in as it settles. Taps during a transition only
    /// change `requestedID`, so every step still runs in order. The steps follow a fixed
    /// schedule because animation completion callbacks can arrive late.
    private func settle(reduceMotion: Bool) async {
        isTransitioning = true
        defer { isTransitioning = false }

        let resizeDuration = reduceMotion ? 0.12 : 0.34
        // No bounce, so the card is at rest by the time the details are fully in.
        let resizeAnimation: Animation = reduceMotion
            ? .easeInOut(duration: resizeDuration)
            : .smooth(duration: resizeDuration)
        let fadeInDuration = reduceMotion ? 0.14 : 0.26
        let fadeOutDuration = reduceMotion ? 0.08 : 0.14
        // The details start to fade in as the card slows to its full size, so opening
        // reads as one movement rather than two.
        let fadeInLead = reduceMotion ? 0 : resizeDuration * 0.35

        while expandedID != requestedID || revealedID != requestedID {
            if revealedID != nil, revealedID != requestedID {
                withAnimation(.easeIn(duration: fadeOutDuration)) { revealedID = nil }
                try? await Task.sleep(for: .seconds(fadeOutDuration))
            } else if expandedID != requestedID {
                withAnimation(resizeAnimation) { expandedID = requestedID }
                if requestedID != nil {
                    try? await Task.sleep(for: .seconds(resizeDuration - fadeInLead))
                }
            } else {
                withAnimation(.easeOut(duration: fadeInDuration)) { revealedID = requestedID }
                try? await Task.sleep(for: .seconds(fadeInDuration))
            }
        }
    }
}

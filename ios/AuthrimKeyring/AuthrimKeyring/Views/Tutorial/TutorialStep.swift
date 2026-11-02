import SwiftUI

/// Parts of the home screen the tutorial points at.
enum TutorialTarget: Hashable {
    case add
    case cards
    case settings
}

struct TutorialStep: Identifiable {
    let id: Int
    let target: TutorialTarget
    let title: LocalizedStringKey
    let message: LocalizedStringKey

    static let all: [TutorialStep] = [
        TutorialStep(
            id: 0,
            target: .add,
            title: "Add an Account",
            message: "Scan the QR code a service shows when you turn on two-factor authentication. You can also choose a screenshot or enter the setup key."
        ),
        TutorialStep(
            id: 1,
            target: .cards,
            title: "Show a Code",
            message: "Each account appears as a card. Tap a card to show its current code, then tap the code to copy it."
        ),
        TutorialStep(
            id: 2,
            target: .cards,
            title: "Customize a Card",
            message: "Touch and hold a card to rename it, change its color, or delete it."
        ),
        TutorialStep(
            id: 3,
            target: .settings,
            title: "Lock, Sync and Back Up",
            message: "In Settings you can turn on the app lock, sync with iCloud Keychain, and export an encrypted backup."
        ),
    ]
}

/// Finds where tutorial targets are on screen, in window coordinates.
///
/// Content views carry a small UIKit probe. Toolbar buttons become UIKit bar
/// buttons that drop such modifiers and carry no label on their views, so they
/// are found by position among the icon buttons on screen instead: a row along
/// the top, or a column down the side as on a closed iPhone Duo.
@MainActor
final class TutorialAnchors {
    /// Which end of the navigation bar a toolbar button sits at.
    enum BarEdge {
        case leading
        case trailing
    }

    private final class WeakView {
        weak var view: UIView?
        init(_ view: UIView) { self.view = view }
    }

    private var views: [TutorialTarget: WeakView] = [:]
    private var barEdges: [TutorialTarget: BarEdge] = [:]
    private weak var host: UIView?

    fileprivate func register(_ view: UIView, for target: TutorialTarget?) {
        if let target {
            views[target] = WeakView(view)
        } else {
            host = view
        }
    }

    /// Marks a target as the outermost toolbar button at `edge`.
    func setBarEdge(_ edge: BarEdge, for target: TutorialTarget) {
        barEdges[target] = edge
    }

    func frame(of target: TutorialTarget) -> CGRect? {
        if let edge = barEdges[target] {
            return barButtonFrame(at: edge)
        }
        guard let view = views[target]?.view, view.window != nil else { return nil }
        return Self.windowFrame(of: view)
    }

    private func barButtonFrame(at edge: BarEdge) -> CGRect? {
        guard let host, let window = host.window else { return nil }
        // Bar buttons are small icon buttons; the large title is also a control, but wider.
        let buttons = Self.outermostControls(in: window)
            .compactMap(Self.windowFrame(of:))
            .filter { $0.width <= Self.maximumIconSize && $0.height <= Self.maximumIconSize }
            .filter { window.bounds.contains(CGPoint(x: $0.midX, y: $0.midY)) }
        guard let first = buttons.min(by: { $0.minY < $1.minY }) else { return nil }

        // A column down the side, as on a closed iPhone Duo: two or more buttons
        // stacked at the same place across. Its toolbar group starts at the top; a
        // search button further down belongs to another group.
        let columns = Dictionary(grouping: buttons) { ($0.midX / 8).rounded() }.values
        if let column = columns.filter({ $0.count > 1 }).max(by: { $0.count < $1.count }) {
            let stacked = column.sorted { $0.minY < $1.minY }
            var group = [stacked[0]]
            for frame in stacked.dropFirst() {
                guard let last = group.last, frame.minY - last.maxY < last.height else { break }
                group.append(frame)
            }
            if group.count > 1 {
                return edge == .leading ? group.first : group.last
            }
        }

        // A row along the top.
        let row = buttons.filter { abs($0.midY - first.midY) < first.height / 2 }
        guard let leftmost = row.min(by: { $0.minX < $1.minX }),
              let rightmost = row.max(by: { $0.maxX < $1.maxX })
        else { return nil }
        let isRightToLeft = host.effectiveUserInterfaceLayoutDirection == .rightToLeft
        return (edge == .leading) != isRightToLeft ? leftmost : rightmost
    }

    private static let maximumIconSize: CGFloat = 60

    private static func windowFrame(of view: UIView) -> CGRect? {
        guard view.window != nil else { return nil }
        // Hidden through any ancestor, as a bar left over from another layout can be.
        var current: UIView? = view
        while let shown = current {
            guard !shown.isHidden, shown.alpha > 0 else { return nil }
            current = shown.superview
        }
        let frame = view.convert(view.bounds, to: nil)
        return frame.isEmpty ? nil : frame
    }

    /// Controls not nested in another control, i.e. one per bar button. A search
    /// field the bar may hold is not a button.
    private static func outermostControls(in view: UIView) -> [UIView] {
        view.subviews.flatMap { subview -> [UIView] in
            if subview is UISearchBar || subview is UITextField { return [] }
            return subview is UIControl ? [subview] : outermostControls(in: subview)
        }
    }
}

extension View {
    /// Lets the tutorial point at this view.
    func tutorialTarget(_ target: TutorialTarget, anchors: TutorialAnchors) -> some View {
        background(AnchorProbe(target: target, anchors: anchors).allowsHitTesting(false))
    }

    /// Gives the tutorial a view inside the navigation stack, used to reach its bar.
    func tutorialHost(_ anchors: TutorialAnchors) -> some View {
        background(AnchorProbe(target: nil, anchors: anchors).allowsHitTesting(false))
    }
}

private struct AnchorProbe: UIViewRepresentable {
    let target: TutorialTarget?
    let anchors: TutorialAnchors

    func makeUIView(context: Context) -> UIView {
        let view = UIView()
        view.isUserInteractionEnabled = false
        view.isAccessibilityElement = false
        anchors.register(view, for: target)
        return view
    }

    func updateUIView(_ view: UIView, context: Context) {
        anchors.register(view, for: target)
    }
}

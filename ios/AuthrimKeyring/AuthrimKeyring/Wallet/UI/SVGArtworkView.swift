import SwiftUI
import WebKit

/// Displays a checked SVG as an image. The document has no scripts, cookies, navigation, or
/// network-capable CSP source. The SVG is an <img>, so WebKit treats it as an image document.
struct SVGArtworkView: UIViewRepresentable {
    enum Fit: String { case contain, cover }

    let data: Data
    let fit: Fit

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        configuration.defaultWebpagePreferences.allowsContentJavaScript = false
        let view = WKWebView(frame: .zero, configuration: configuration)
        view.navigationDelegate = context.coordinator
        view.isOpaque = false
        view.backgroundColor = .clear
        view.underPageBackgroundColor = .clear
        view.scrollView.backgroundColor = .clear
        view.scrollView.isScrollEnabled = false
        view.isUserInteractionEnabled = false
        view.accessibilityElementsHidden = true
        return view
    }

    func updateUIView(_ view: WKWebView, context: Context) {
        guard context.coordinator.lastData != data || context.coordinator.lastFit != fit else { return }
        context.coordinator.lastData = data
        context.coordinator.lastFit = fit
        let encoded = data.base64EncodedString()
        let html = """
        <!doctype html><html><head>
        <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
        <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
        <style>html,body{margin:0;width:100%;height:100%;overflow:hidden;background:transparent}img{display:block;width:100%;height:100%;object-fit:\(fit.rawValue)}</style>
        </head><body><img src="data:image/svg+xml;base64,\(encoded)" alt=""></body></html>
        """
        view.loadHTMLString(html, baseURL: nil)
    }

    final class Coordinator: NSObject, WKNavigationDelegate {
        var lastData: Data?
        var lastFit: Fit?

        func webView(
            _ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
            decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
        ) {
            // loadHTMLString starts at about:blank. No link or issuer-supplied navigation is allowed.
            let scheme = navigationAction.request.url?.scheme?.lowercased()
            decisionHandler(scheme == nil || scheme == "about" ? .allow : .cancel)
        }
    }
}

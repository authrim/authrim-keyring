import Foundation

/// Unicode isolate controls set the paragraph's base direction without flipping the card layout.
nonisolated enum CredentialTextDirection: String, Codable, Hashable, Sendable {
    case ltr, rtl, auto

    func isolate(_ text: String) -> String {
        let prefix: String
        switch self {
        case .ltr: prefix = "\u{2066}" // LRI
        case .rtl: prefix = "\u{2067}" // RLI
        case .auto: prefix = "\u{2068}" // FSI: first strong character
        }
        return prefix + text + "\u{2069}" // PDI
    }
}

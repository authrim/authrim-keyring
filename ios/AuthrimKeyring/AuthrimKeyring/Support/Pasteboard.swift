import UIKit
import UniformTypeIdentifiers

enum Pasteboard {
    /// Copies a one-time code without Universal Clipboard and clears it after a short time.
    static func copySensitive(_ text: String, expiresAfter seconds: TimeInterval) {
        UIPasteboard.general.setItems(
            [[UTType.plainText.identifier: text]],
            options: [
                .localOnly: true,
                .expirationDate: Date.now.addingTimeInterval(seconds),
            ]
        )
    }
}

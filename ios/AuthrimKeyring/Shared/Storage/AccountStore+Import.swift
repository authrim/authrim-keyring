import Foundation

/// Passkeys moved in from another app.
extension AccountStore {
    /// Adds passkeys, skipping any already here, with their favorites and tags.
    func importPasskeys(_ incoming: [Passkey], meta incomingMeta: [ItemMeta] = []) -> ImportResult {
        // Read again, so a passkey added meanwhile is not added twice.
        load()
        // Without every passkey read, one already here could be added again.
        guard !arePasskeysUnavailable else {
            return ImportResult(added: 0, error: String(localized: "Passkeys could not be read from the Keychain. Try again after restarting the app."))
        }
        let notes = Dictionary(incomingMeta.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        var added = 0
        for passkey in incoming where !containsPasskey(like: passkey) {
            do {
                try addPasskey(passkey)
                if let note = notes[passkey.id], !isMetaUnavailable {
                    try saveMeta(note)
                }
            } catch {
                return ImportResult(added: added, error: error.localizedDescription)
            }
            added += 1
        }
        return ImportResult(added: added, error: nil)
    }

    /// Whether the same passkey, for the same site, is already here.
    func containsPasskey(like passkey: Passkey) -> Bool {
        passkeys.contains { $0.relyingParty == passkey.relyingParty && $0.credentialID == passkey.credentialID }
    }
}

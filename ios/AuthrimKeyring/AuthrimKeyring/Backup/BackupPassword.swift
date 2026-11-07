import Foundation
import Security

/// Rules for the password of a new backup. A leaked file can be tried against guesses
/// offline, so short and common passwords are refused. Restoring takes any password,
/// so files made with older rules still open.
nonisolated enum BackupPassword {
    static let minimumLength = 12

    enum Weakness: Equatable {
        case tooShort
        case easyToGuess
    }

    static func weakness(of password: String) -> Weakness? {
        let characters = Array(password.precomposedStringWithCanonicalMapping.lowercased())
        guard characters.count >= minimumLength else { return .tooShort }
        // Few different characters, as in "aaaaaaaaaaaa" or "abababababab", unless the
        // password is long enough to make up for it (about 60 bits).
        let distinct = Set(characters).count
        if distinct < 5, Double(characters.count) * log2(Double(max(distinct, 1))) < 60 { return .easyToGuess }
        // A short piece repeated, as in "123451234512".
        if (1...characters.count / 2).contains(where: { isRepeated(characters, every: $0) }) { return .easyToGuess }
        // A run such as "123456789012" or "abcdefghijkl", either way.
        let steps = zip(characters, characters.dropFirst()).compactMap { pair -> Int? in
            guard let left = pair.0.unicodeScalars.first?.value, let right = pair.1.unicodeScalars.first?.value
            else { return nil }
            return Int(right) - Int(left)
        }
        if steps.filter({ abs($0) == 1 || abs($0) == 9 }).count >= steps.count - 1 { return .easyToGuess }
        // A common word, perhaps spelled with digits or symbols ("p@ssw0rd"), with only
        // digits or symbols around it, as in "password1234".
        let word = String(characters.drop(while: { !$0.isLetter }).reversed().drop(while: { !$0.isLetter }).reversed())
        let letters = String(word.map { lookalikes[$0] ?? $0 }.filter(\.isLetter))
        if commonWords.contains(where: { letters == $0 || letters == $0 + $0 }) { return .easyToGuess }
        return nil
    }

    private static func isRepeated(_ characters: [Character], every period: Int) -> Bool {
        characters.indices.dropFirst(period).allSatisfy { characters[$0] == characters[$0 - period] }
    }

    private static let lookalikes: [Character: Character] = [
        "@": "a", "4": "a", "8": "b", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t",
    ]

    private static let commonWords: Set<String> = [
        "password", "passw", "pass", "passwort", "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbnm",
        "letmein", "welcome", "iloveyou", "admin", "administrator", "login", "secret", "changeme", "monkey",
        "dragon", "shadow", "sunshine", "princess", "football", "baseball", "soccer", "master", "superman",
        "batman", "starwars", "whatever", "freedom", "hello", "computer", "internet", "summer", "winter",
        "keyring", "authrim", "backup", "abc",
    ]

    /// A random password of four groups of five letters and digits, such as
    /// `k3v9q-…`: about 100 bits, and easy to write down.
    static func suggestion() -> String {
        let alphabet = Array("abcdefghijkmnpqrstuvwxyz23456789")
        var bytes = [UInt8](repeating: 0, count: 20)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            return (0..<4).map { _ in String((0..<5).map { _ in alphabet.randomElement()! }) }.joined(separator: "-")
        }
        // 32 characters, so each byte picks one evenly.
        let characters = bytes.map { alphabet[Int($0) % alphabet.count] }
        return stride(from: 0, to: characters.count, by: 5)
            .map { String(characters[$0..<$0 + 5]) }
            .joined(separator: "-")
    }
}

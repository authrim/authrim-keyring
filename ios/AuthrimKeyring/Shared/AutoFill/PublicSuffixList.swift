import Foundation

/// The Public Suffix List (https://publicsuffix.org/list/), bundled as `public_suffix_list.dat`:
/// the suffixes under which unrelated owners have names, such as `co.uk` or `github.io`.
/// The app never fetches it; replace the file from that address before a release.
nonisolated struct PublicSuffixList: Sendable {
    private let rules: Set<String>
    /// `*.ck` is kept as `ck`: every name directly under it is a suffix.
    private let wildcards: Set<String>
    /// `!www.ck` is kept as `www.ck`: an exception to a wildcard, owned by one owner.
    private let exceptions: Set<String>
    /// Every name with a suffix somewhere under it, such as `amazonaws.com` for
    /// `*.compute.amazonaws.com`.
    private let ancestors: Set<String>

    /// The bundled list, or nil when it is missing or empty.
    static let bundled: PublicSuffixList? = {
        guard let url = Bundle.main.url(forResource: "public_suffix_list", withExtension: "dat"),
              let text = try? String(contentsOf: url, encoding: .utf8)
        else { return nil }
        let list = PublicSuffixList(text)
        return list.rules.isEmpty ? nil : list
    }()

    init(_ text: String) {
        var rules = Set<String>()
        var wildcards = Set<String>()
        var exceptions = Set<String>()
        for line in text.split(whereSeparator: \.isNewline) {
            // A rule is the line up to the first white space; comments start with //.
            guard let word = line.split(whereSeparator: \.isWhitespace).first, !word.hasPrefix("//") else { continue }
            if word.hasPrefix("!") {
                if let rule = Self.ascii(word.dropFirst()) { exceptions.insert(rule) }
            } else if word.hasPrefix("*.") {
                if let rule = Self.ascii(word.dropFirst(2)) { wildcards.insert(rule) }
            } else if let rule = Self.ascii(word) {
                rules.insert(rule)
            }
        }
        self.rules = rules
        self.wildcards = wildcards
        self.exceptions = exceptions
        var ancestors = wildcards
        for rule in rules.union(wildcards) {
            var labels = rule.split(separator: ".")
            while labels.count > 1 {
                labels.removeFirst()
                ancestors.insert(labels.joined(separator: "."))
            }
        }
        self.ancestors = ancestors
    }

    /// Whether names directly under `domain` can belong to different owners.
    /// `domain` is lowercase ASCII, with internationalized labels in punycode.
    func isPublicSuffix(_ domain: String) -> Bool {
        let labels = domain.split(separator: ".", omittingEmptySubsequences: false)
        // Every top-level domain is one, listed or not.
        guard labels.count > 1 else { return true }
        if exceptions.contains(domain) { return false }
        return rules.contains(domain) || wildcards.contains(labels.dropFirst().joined(separator: "."))
    }

    /// The name one label longer than the public suffix of `host`, which one owner
    /// controls: `example.co.uk` for `login.example.co.uk`. Nil when `host` is itself a suffix.
    func registrableDomain(of host: String) -> String? {
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        // The longest match wins, so the search starts from the left.
        for start in labels.indices {
            let candidate = labels[start...].joined(separator: ".")
            // An exception names a domain whose parent is the suffix, listed or not.
            if exceptions.contains(candidate) { return candidate }
            if isPublicSuffix(candidate) {
                return start == 0 ? nil : labels[(start - 1)...].joined(separator: ".")
            }
        }
        return nil
    }

    /// Whether some name under `domain` is a public suffix, so that names further down
    /// can belong to owners other than the one of `domain`.
    func hasSuffixesBeneath(_ domain: String) -> Bool {
        ancestors.contains(domain)
    }

    /// A rule as hosts are compared: lowercase, internationalized labels in punycode.
    private static func ascii(_ rule: Substring) -> String? {
        let labels = rule.lowercased().split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.contains(where: \.isEmpty) else { return nil }
        let converted = labels.compactMap { punycode(String($0)) }
        return converted.count == labels.count ? converted.joined(separator: ".") : nil
    }

    /// The ASCII form of one label (RFC 3492), `xn--` and all; ASCII labels are returned as they are.
    static func punycode(_ label: String) -> String? {
        let code = label.unicodeScalars.map { Int($0.value) }
        guard code.contains(where: { $0 >= 0x80 }) else { return label }
        let base = 36, tMin = 1, tMax = 26
        var output = String(label.unicodeScalars.filter(\.isASCII))
        let basicCount = output.count
        var handled = basicCount
        if basicCount > 0 { output.append("-") }
        var n = 0x80, delta = 0, bias = 72

        func digit(_ value: Int) -> Character {
            Character(UnicodeScalar(UInt8(value < 26 ? 0x61 + value : 0x30 + value - 26)))
        }
        func adapt(_ delta: Int, _ points: Int, _ first: Bool) -> Int {
            var delta = first ? delta / 700 : delta / 2
            delta += delta / points
            var k = 0
            while delta > ((base - tMin) * tMax) / 2 {
                delta /= base - tMin
                k += base
            }
            return k + (base - tMin + 1) * delta / (delta + 38)
        }

        while handled < code.count {
            guard let next = code.filter({ $0 >= n }).min() else { return nil }
            delta += (next - n) * (handled + 1)
            n = next
            for scalar in code {
                if scalar < n { delta += 1 }
                guard scalar == n else { continue }
                var q = delta
                var k = base
                while true {
                    let t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias)
                    if q < t { break }
                    output.append(digit(t + (q - t) % (base - t)))
                    q = (q - t) / (base - t)
                    k += base
                }
                output.append(digit(q))
                bias = adapt(delta, handled + 1, handled == basicCount)
                delta = 0
                handled += 1
            }
            delta += 1
            n += 1
        }
        return "xn--" + output
    }
}

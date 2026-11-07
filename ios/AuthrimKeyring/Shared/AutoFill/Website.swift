import Foundation

/// Domains a card's codes are offered on by AutoFill.
nonisolated enum Website {
    static let maximumPerAccount = 20

    /// The bare host of what the user typed: `https://www.Example.com/login` becomes
    /// `example.com`. Nil when it does not look like a domain.
    static func normalized(_ text: String) -> String? {
        var candidate = text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !candidate.isEmpty else { return nil }
        if !candidate.contains("://") {
            candidate = "https://" + candidate
        }
        guard var host = URLComponents(string: candidate)?.host, host.count <= 253 else { return nil }
        if host.hasSuffix(".") { host.removeLast() }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2,
              labels.allSatisfy({ !$0.isEmpty && $0.count <= 63 && $0.allSatisfy(isHostCharacter) })
        else { return nil }
        let site = host.hasPrefix("www.") ? String(host.dropFirst(4)) : host
        // A suffix shared by unrelated sites would match all of them.
        return isSharedSuffix(site) ? nil : site
    }

    /// Whether names under `site` can belong to different owners, such as `co.uk` or
    /// `github.io`, by the bundled Public Suffix List. If the list cannot be read, a short
    /// list of the most common ones stands in for it.
    static func isSharedSuffix(_ site: String) -> Bool {
        let site = ascii(site)
        if let list = PublicSuffixList.bundled { return list.isPublicSuffix(site) }
        let labels = site.split(separator: ".")
        if labels.count == 2, labels[1].count == 2, genericSecondLevel.contains(String(labels[0])) {
            return true
        }
        return sharedHosting.contains(site)
    }

    private static let genericSecondLevel: Set<String> = [
        "ac", "co", "com", "edu", "go", "gov", "gr", "lg", "ltd", "ne", "net", "or", "org", "plc", "sch",
    ]

    private static let sharedHosting: Set<String> = [
        "github.io", "gitlab.io", "pages.dev", "workers.dev", "vercel.app", "netlify.app",
        "herokuapp.com", "appspot.com", "web.app", "firebaseapp.com", "blogspot.com",
        "azurewebsites.net", "cloudfront.net", "s3.amazonaws.com", "onrender.com", "fly.dev",
    ]

    /// Whether a page on `host` may be offered the codes of a card set for `site`: the site
    /// itself, or one of its subdomains with the same owner. Also checks sites saved or
    /// imported before a suffix was known, so that a site such as `pages.dev` never covers
    /// unrelated subdomains.
    static func matches(host: String, site: String) -> Bool {
        let host = ascii(host)
        let site = ascii(site)
        if host == site { return true }
        guard host.hasSuffix("." + site) else { return false }
        guard let list = PublicSuffixList.bundled else { return !isSharedSuffix(site) }
        // The owner of `host` must own `site` too, so no suffix lies between them.
        guard let owner = list.registrableDomain(of: host) else { return false }
        return site == owner || site.hasSuffix("." + owner)
    }

    /// Whether the codes of a card set for `site` may be suggested above the keyboard,
    /// where the system, not Keyring, picks the pages that see them. Not for a shared
    /// suffix, nor for a name with shared suffixes under it, such as `amazonaws.com`;
    /// Keyring's own list, which checks the page itself, still suggests those.
    static func canSuggestAboveKeyboard(_ site: String) -> Bool {
        guard !isSharedSuffix(site) else { return false }
        return !(PublicSuffixList.bundled?.hasSuffixesBeneath(ascii(site)) ?? false)
    }

    /// `host` as the Public Suffix List is compared: lowercase, with internationalized
    /// labels in punycode, so that `公司.cn` is recognized as `xn--55qx5d.cn`.
    static func ascii(_ host: String) -> String {
        host.lowercased()
            .split(separator: ".", omittingEmptySubsequences: false)
            .map { PublicSuffixList.punycode(String($0)) ?? String($0) }
            .joined(separator: ".")
    }

    /// Whether `host` is `site` or any name under it, owner or not. For rules where
    /// covering more is the cautious side, such as which passkeys stay on this device.
    static func isSameOrSubdomain(_ host: String, of site: String) -> Bool {
        let host = host.lowercased()
        return host == site || host.hasSuffix("." + site)
    }

    /// A site to add automatically: only an issuer that is itself a domain, since a
    /// service name such as “GitLab” may stand for a self-hosted server.
    static func domain(fromIssuer issuer: String) -> String? {
        issuer.contains(".") && !issuer.contains(" ") ? normalized(issuer) : nil
    }

    /// A site to offer for a card, from a well-known service name or an issuer that
    /// is itself a domain. The user confirms it before it is used.
    static func guess(for issuer: String) -> String? {
        let key = issuer.lowercased().filter { $0.isLetter || $0.isNumber || $0 == "." }
        if let known = wellKnown[key] { return known }
        if key.contains("."), let domain = normalized(issuer) { return domain }
        return nil
    }

    private static func isHostCharacter(_ character: Character) -> Bool {
        character.isASCII && (character.isLetter || character.isNumber || character == "-")
    }

    private static let wellKnown: [String: String] = [
        "github": "github.com",
        "gitlab": "gitlab.com",
        "bitbucket": "bitbucket.org",
        "google": "google.com",
        "microsoft": "microsoft.com",
        "amazon": "amazon.com",
        "amazonwebservices": "aws.amazon.com",
        "aws": "aws.amazon.com",
        "facebook": "facebook.com",
        "meta": "facebook.com",
        "instagram": "instagram.com",
        "x": "x.com",
        "twitter": "x.com",
        "discord": "discord.com",
        "dropbox": "dropbox.com",
        "slack": "slack.com",
        "cloudflare": "cloudflare.com",
        "npm": "npmjs.com",
        "pypi": "pypi.org",
        "digitalocean": "digitalocean.com",
        "heroku": "heroku.com",
        "paypal": "paypal.com",
        "stripe": "stripe.com",
        "linkedin": "linkedin.com",
        "reddit": "reddit.com",
        "twitch": "twitch.tv",
        "epicgames": "epicgames.com",
        "coinbase": "coinbase.com",
        "proton": "proton.me",
        "protonmail": "proton.me",
        "atlassian": "atlassian.com",
        "notion": "notion.so",
        "figma": "figma.com",
        "zoom": "zoom.us",
        "yahoo": "yahoo.com",
        "yahoojapan": "yahoo.co.jp",
    ]
}

import Foundation
import Testing
@testable import AuthrimKeyring

struct PublicSuffixListTests {
    private let list = PublicSuffixList("""
        // A comment, then normal, wildcard and exception rules.
        com
        uk
        co.uk
        github.io
        *.ck
        !www.ck
        *.compute.example.com
        公司.cn
        """)

    @Test func bundledListLoads() throws {
        let bundled = try #require(PublicSuffixList.bundled)
        #expect(bundled.isPublicSuffix("co.uk"))
        #expect(bundled.isPublicSuffix("github.io"))
        #expect(bundled.isPublicSuffix("pages.dev"))
        #expect(!bundled.isPublicSuffix("example.com"))
    }

    @Test func rules() {
        #expect(list.isPublicSuffix("com"))
        #expect(list.isPublicSuffix("anything"))
        #expect(list.isPublicSuffix("co.uk"))
        #expect(list.isPublicSuffix("github.io"))
        #expect(list.isPublicSuffix("foo.ck"))
        #expect(!list.isPublicSuffix("www.ck"))
        #expect(list.isPublicSuffix("xn--55qx5d.cn"))
        #expect(!list.isPublicSuffix("example.co.uk"))
        #expect(!list.isPublicSuffix("compute.example.com"))
    }

    @Test func exceptionsUnderAnUnlistedParent() throws {
        // `kawasaki.jp` itself is not listed; `city.kawasaki.jp` belongs to one owner.
        let bundled = try #require(PublicSuffixList.bundled)
        #expect(bundled.registrableDomain(of: "www.city.kawasaki.jp") == "city.kawasaki.jp")
        #expect(bundled.registrableDomain(of: "www.example.kawasaki.jp") == "www.example.kawasaki.jp")
        #expect(bundled.hasSuffixesBeneath("kawasaki.jp"))
        #expect(!Website.matches(host: "www.city.kawasaki.jp", site: "kawasaki.jp"))
        #expect(Website.matches(host: "www.city.kawasaki.jp", site: "city.kawasaki.jp"))
    }

    @Test func registrableDomain() {
        #expect(list.registrableDomain(of: "login.example.co.uk") == "example.co.uk")
        #expect(list.registrableDomain(of: "alice.github.io") == "alice.github.io")
        #expect(list.registrableDomain(of: "a.b.www.ck") == "www.ck")
        #expect(list.registrableDomain(of: "x.tenant.compute.example.com") == "x.tenant.compute.example.com")
        #expect(list.registrableDomain(of: "github.io") == nil)
    }

    @Test(arguments: [
        ("公司", "xn--55qx5d"),
        ("aéroport", "xn--aroport-bya"),
        ("bücher", "xn--bcher-kva"),
        ("example", "example"),
    ])
    func punycode(label: String, expected: String) {
        #expect(PublicSuffixList.punycode(label) == expected)
    }
}

struct WebsiteTests {
    @Test func subdomainsOfAnOwnedSiteMatch() {
        #expect(Website.matches(host: "example.com", site: "example.com"))
        #expect(Website.matches(host: "Login.Example.com", site: "example.com"))
        #expect(Website.matches(host: "a.login.example.co.uk", site: "login.example.co.uk"))
        #expect(!Website.matches(host: "badexample.com", site: "example.com"))
    }

    @Test func aSharedSuffixNeverCoversItsTenants() {
        // As saved or imported by a version without the full list.
        #expect(!Website.matches(host: "attacker.pages.dev", site: "pages.dev"))
        #expect(!Website.matches(host: "attacker.github.io", site: "github.io"))
        #expect(Website.matches(host: "pages.dev", site: "pages.dev"))
        #expect(Website.matches(host: "www.alice.github.io", site: "alice.github.io"))
    }

    @Test func aSiteAboveASuffixDoesNotCoverTheNamesUnderIt() throws {
        // `*.compute.amazonaws.com` is listed, so its tenants are not amazonaws.com's.
        let tenant = "attacker.eu-west-1.compute.amazonaws.com"
        #expect(try #require(PublicSuffixList.bundled).registrableDomain(of: tenant) == tenant)
        #expect(!Website.matches(host: tenant, site: "compute.amazonaws.com"))
    }

    @Test func internationalizedNamesAreComparedInPunycode() {
        // As a restored backup or the system may give them.
        #expect(Website.isSharedSuffix("公司.cn"))
        #expect(!Website.matches(host: "attacker.公司.cn", site: "公司.cn"))
        #expect(!Website.matches(host: "attacker.xn--55qx5d.cn", site: "公司.cn"))
        #expect(Website.matches(host: "www.Bücher.example", site: "xn--bcher-kva.example"))
    }

    @Test func keyboardSuggestionsSkipNamesAboveSharedSuffixes() {
        #expect(Website.canSuggestAboveKeyboard("example.com"))
        #expect(Website.canSuggestAboveKeyboard("login.example.co.uk"))
        #expect(!Website.canSuggestAboveKeyboard("pages.dev"))
        #expect(!Website.canSuggestAboveKeyboard("amazonaws.com"))
        #expect(!Website.canSuggestAboveKeyboard("kawasaki.jp"))
        // The well-known services offered when a card is added stay suggestible.
        for site in ["github.com", "google.com", "microsoft.com", "aws.amazon.com", "yahoo.co.jp", "x.com"] {
            #expect(Website.canSuggestAboveKeyboard(site), "\(site)")
        }
    }

    @Test func sharedSuffixesAreNotAccepted() {
        #expect(Website.normalized("https://pages.dev") == nil)
        #expect(Website.normalized("myshopify.com") == nil)
        #expect(Website.normalized("co.jp") == nil)
        #expect(Website.normalized("https://www.Example.co.jp/login") == "example.co.jp")
    }

    @Test func autoFillSkipsSharedSuffixes() {
        let account = OTPAccount(issuer: "Northwind", accountName: "alex", secret: Data([1, 2, 3, 4, 5]))
        let details = AccountDetails(id: account.id, websites: ["pages.dev", "amazonaws.com", "northwind.example"])
        let identities = CredentialIdentitySync.identities(accounts: [account], details: [account.id: details], passkeys: [])
        #expect(identities.codes.map(\.site) == ["northwind.example"])
    }

    @Test func deviceOnlyRulesStillCoverEverySubdomain() {
        let defaults = UserDefaults(suiteName: "WebsiteTests.\(UUID().uuidString)")!
        PasskeySyncRules.setDeviceOnly(true, for: "pages.dev", in: defaults)
        #expect(PasskeySyncRules.isDeviceOnly("tenant.pages.dev", in: defaults))
    }
}

struct CounterLockTests {
    @Test func runsTheBodyAndReturnsItsValue() throws {
        #expect(try CounterLock.withLock { 42 } == 42)
    }

    @Test func excludesAnotherHolderAndGivesUp() throws {
        let started = ContinuousClock.now
        // A second open file is another holder, as in the AutoFill extension.
        #expect(throws: CounterLock.Unavailable.self) {
            try CounterLock.withLock { try CounterLock.withLock { () } }
        }
        #expect(ContinuousClock.now - started >= CounterLock.timeout)
    }
}

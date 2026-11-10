import Foundation
import SwiftUI

/// Made-up cards that stand in for the user's own, to show the app to someone.
///
/// They live under their own Keychain service and settings domain, are never synced and
/// never offered to AutoFill, so the user's own cards stay as they were. Turning Demo Mode
/// off deletes the made-up ones. Credentials are kept in memory only.
enum DemoMode {
    /// The setting, in the app's own defaults.
    static let key = "demoMode"
    private static let service = "com.authrim.keyring.demo"

    private static var defaults: UserDefaults {
        UserDefaults(suiteName: service) ?? .standard
    }

    /// The stores the app shows while Demo Mode is on.
    @MainActor
    final class Session {
        let store: AccountStore
        let wallet: WalletModel

        /// `fresh` starts over with the made-up cards; otherwise those left from before are read.
        init(fresh: Bool) {
            if fresh {
                UserDefaults().removePersistentDomain(forName: service)
            }
            store = AccountStore(keychain: KeychainStore(service: service), defaults: defaults)
            if fresh {
                store.deleteAll()
                DemoMode.fill(store)
            } else {
                store.load()
            }
            wallet = WalletModel(issuance: DemoIssuance(), store: DemoCredentialStore(credentials: DemoMode.credentials))
            wallet.load()
        }

        /// Deletes the made-up cards.
        func end() {
            store.deleteAll()
            UserDefaults().removePersistentDomain(forName: service)
        }
    }

    @MainActor
    private static func fill(_ store: AccountStore) {
        let start = Date.now.addingTimeInterval(-120 * 24 * 3600)
        for (index, (issuer, name)) in accounts.enumerated() {
            let account = OTPAccount(
                issuer: issuer,
                accountName: name,
                secret: Data((0..<20).map { UInt8(truncatingIfNeeded: $0 * 37 + index * 101 + 7) }),
                // Keeps the listed order, which falls back to creation time.
                createdAt: start.addingTimeInterval(Double(index) * 3600),
                cardColor: CardColor.presets[index % CardColor.presets.count]
            )
            store.add(account)
        }
        for (index, (site, title)) in passkeys.enumerated() {
            // Not in the Secure Enclave: these keys are thrown away with the cards.
            guard let made = try? Passkey.make(
                relyingParty: site,
                userName: "alex@example.com",
                userHandle: Data("alex-\(index)".utf8),
                deviceOnly: false,
                now: start.addingTimeInterval(Double(index) * 7200)
            ) else { continue }
            var passkey = made.passkey
            passkey.customTitle = title
            passkey.lastUsedAt = .now.addingTimeInterval(-Double(index + 1) * 26 * 3600)
            try? store.addPasskey(passkey)
        }
        for item in store.items where ["Authrim", "Northwind Mail", "Juniper Travel"].contains(item.displayTitle) {
            store.setFavorite(true, for: item.id)
        }
        for account in store.accounts where ["Acme Cloud", "Pixel Forge", "Willow Docs"].contains(account.issuer) {
            store.setTags(["Work"], for: account.id)
        }
    }

    private static let accounts: [(String, String)] = [
        ("Authrim", "alex@example.com"),
        ("Northwind Mail", "alex@northwind.example"),
        ("Acme Cloud", "admin@acme.example"),
        ("Harbor Bank", "alex.morgan"),
        ("Fern Notes", "alex@example.com"),
        ("Lumen Shop", "alex"),
        ("Pixel Forge", "alex@pixelforge.example"),
        ("Orbit Chat", "alex"),
        ("Cedar Games", "alex.morgan"),
        ("Willow Docs", "alex@example.com"),
        ("Tidal Pay", "alex@example.com"),
        ("Summit Fitness", "alex.m"),
    ]

    private static let passkeys: [(String, String)] = [
        ("juniper.example", "Juniper Travel"),
        ("maple.example", "Maple Market"),
        ("quartz.example", "Quartz Bank"),
        ("aurora.example", "Aurora Photos"),
        ("birch.example", "Birch Books"),
        ("coral.example", "Coral Music"),
        ("delta.example", "Delta Air"),
        ("ember.example", "Ember Studio"),
        ("flint.example", "Flint Code"),
        ("grove.example", "Grove Health"),
        ("heron.example", "Heron News"),
    ]

    private static var credentials: [StoredCredential] {
        let day: TimeInterval = 24 * 3600
        let demoLogo = Data("""
            <svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
              <circle cx="32" cy="32" r="29" fill="#E9C977"/>
              <path d="M19 43V21h26v5H25v4h17v5H25v3h20v5z" fill="#102752"/>
            </svg>
            """.utf8)
        let demoFace = Data("""
            <svg xmlns="http://www.w3.org/2000/svg" width="1000" height="640" viewBox="0 0 1000 640">
              <defs>
                <linearGradient id="base" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0" stop-color="#1A478A"/>
                  <stop offset="1" stop-color="#0A1738"/>
                </linearGradient>
                <linearGradient id="ribbon" x1="0" y1="0" x2="1" y2="0">
                  <stop offset="0" stop-color="#E9C977"/>
                  <stop offset="1" stop-color="#B58737"/>
                </linearGradient>
              </defs>
              <rect width="1000" height="640" fill="url(#base)"/>
              <circle cx="905" cy="75" r="350" fill="#3E73BF" opacity=".3"/>
              <circle cx="905" cy="75" r="270" fill="none" stroke="#E9C977" stroke-width="3" opacity=".65"/>
              <circle cx="905" cy="75" r="220" fill="none" stroke="#E9C977" stroke-width="2" opacity=".45"/>
              <path d="M0 510C240 405 445 570 695 455S930 415 1000 390V640H0Z" fill="#102D62" opacity=".65"/>
              <path d="M0 560C275 460 485 620 705 525S940 475 1000 460" fill="none" stroke="url(#ribbon)" stroke-width="9" opacity=".9"/>
              <path d="M35 615H965" stroke="#E9C977" stroke-width="2" opacity=".5"/>
            </svg>
            """.utf8)
        let demoTemplate = Data(String(decoding: demoFace, as: UTF8.self)
            .replacingOccurrences(of: "</svg>", with: """
              <text x="76" y="125" fill="#E9C977" font-size="33" font-weight="700">ADMINISTRATOR CREDENTIAL</text>
              <text x="76" y="310" fill="#FFFFFF" font-size="64" font-weight="700">{{holder}}</text>
              <text x="76" y="365" fill="#E1E8F5" font-size="28">{{role}}</text>
              <text x="76" y="590" fill="#E9C977" font-size="25">EXAMPLE CORPORATION</text>
            </svg>
            """).utf8)
        let renderedDemoFace = SVGImageValidator.renderTemplate(
            demoTemplate, values: ["holder": "Alex Morgan", "role": "Tenant admin"])
        func card(_ background: String, _ text: String, _ description: String? = nil,
                  logo: Data? = nil, face: Data? = nil, template: Data? = nil) -> CredentialDisplay {
            var result = CredentialDisplay(
                description: description, backgroundColor: background, textColor: text,
                logoAltText: logo == nil ? nil : "Example issuer logo", logoData: logo,
                logoMediaType: logo == nil ? nil : "image/svg+xml",
                backgroundImageData: face, backgroundImageMediaType: face == nil ? nil : "image/svg+xml")
            result.faceSVGData = template
            return result
        }
        func credential(
            _ issuer: String, _ issuerName: String?, _ name: String, _ claims: [String: String],
            issuedDaysAgo: Double, validDays: Double?, code: String, confirmed: Bool,
            display: CredentialDisplay? = nil
        ) -> StoredCredential {
            let issued = Date.now.addingTimeInterval(-issuedDaysAgo * day)
            return StoredCredential(
                id: UUID(),
                issuer: URL(string: issuer)!,
                issuerDisplayName: issuerName,
                credentialConfigurationId: "demo",
                vct: issuer + "/vct/demo",
                credentialName: name,
                claims: claims,
                issuedAt: issued,
                expiresAt: validDays.map { issued.addingTimeInterval($0 * day) },
                keyTag: "demo",
                confirmationCode: code,
                sdJwt: "demo~",
                confirmedAt: confirmed ? issued : nil,
                credentialDisplay: display
            )
        }
        return [
            credential("https://id.example.com", "Example Corp", "Administrator Credential",
                       ["Name": "Alex Morgan", "Email": "alex@example.com", "Role": "Tenant admin"],
                       issuedDaysAgo: 12, validDays: 365, code: "K7QM-2XPD", confirmed: true,
                       display: card("#102752", "#FFFFFF", "Administrator access",
                                     logo: demoLogo, face: demoFace, template: renderedDemoFace)),
            credential("https://idp.university.example", "Example University", "Student ID",
                       ["Name": "Alex Morgan", "Student Number": "2026-01234", "Faculty": "Engineering"],
                       issuedDaysAgo: 40, validDays: 1460, code: "R4TN-8WVB", confirmed: true,
                       display: card("#F2E6C9", "#252016", "Student identification")),
            credential("https://hr.northwind.example", "Northwind Inc.", "Employee Badge",
                       ["Name": "Alex Morgan", "Department": "Design", "Employee Number": "NW-0420"],
                       issuedDaysAgo: 90, validDays: 730, code: "C9HZ-3FJE", confirmed: false),
            credential("https://library.city.example", "City Library", "Library Card",
                       ["Name": "Alex Morgan", "Card Number": "LIB-558201"],
                       issuedDaysAgo: 200, validDays: 1095, code: "M2UA-6KYR", confirmed: false),
            credential("https://members.summit.example", "Summit Fitness", "Membership",
                       ["Name": "Alex Morgan", "Plan": "Annual"],
                       issuedDaysAgo: 30, validDays: 335, code: "P8DS-1LQX", confirmed: false),
            credential("https://events.example.org", nil, "Conference Pass",
                       ["Name": "Alex Morgan", "Event": "Identity Summit"],
                       issuedDaysAgo: 400, validDays: 3, code: "W5GB-7NCT", confirmed: false),
        ]
    }
}

/// Offers cannot be received in Demo Mode.
private struct DemoIssuance: CredentialIssuanceService {
    func preview(offer: String) async throws -> CredentialOfferPreview {
        throw WalletError.network(String(localized: "Demo Mode is on. Turn it off in Settings to receive credentials."))
    }

    func issue(_ preview: CredentialOfferPreview, transactionCode: String?) async throws -> StoredCredential {
        throw WalletError.network(String(localized: "Demo Mode is on. Turn it off in Settings to receive credentials."))
    }
}

/// The made-up credentials, kept in memory only.
private final class DemoCredentialStore: CredentialStore, @unchecked Sendable {
    private var credentials: [StoredCredential]

    init(credentials: [StoredCredential]) {
        self.credentials = credentials
    }

    func loadAll() throws -> [StoredCredential] { credentials }
    func save(_ credential: StoredCredential) throws {
        credentials.removeAll { $0.id == credential.id }
        credentials.append(credential)
    }
    func delete(_ credential: StoredCredential) throws { credentials.removeAll { $0.id == credential.id } }
}

/// Shown instead of the add screen, and of what other apps send, while Demo Mode is on.
struct DemoModeAddNotice: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ContentUnavailableView {
                Label("Demo Mode Is On", systemImage: "play.rectangle")
            } description: {
                Text("Turn off Demo Mode in Settings to add your own.")
            }
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
        .presentationDetents([.medium])
    }
}

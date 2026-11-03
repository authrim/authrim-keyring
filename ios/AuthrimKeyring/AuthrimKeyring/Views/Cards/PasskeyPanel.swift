import SwiftUI

/// Detail content of a passkey card: where it is kept and when it was used.
struct PasskeyPanel: View {
    let passkey: Passkey
    let isSyncEnabled: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(storage, systemImage: passkey.isBackupEligible && isSyncEnabled ? "icloud" : "iphone")
                .font(.subheadline.weight(.semibold))
            Text("Created \(passkey.createdAt.formatted(date: .abbreviated, time: .omitted))")
                .font(.caption)
            if let lastUsedAt = passkey.lastUsedAt {
                Text("Last used \(lastUsedAt.formatted(.relative(presentation: .named)))")
                    .font(.caption)
            } else {
                // Saving can still fail on the website's side after Keyring has kept it.
                Text("Not used yet. If the website did not finish setting up this passkey, you can delete it.")
                    .font(.caption)
            }
            Text("Sign in on \(passkey.relyingParty) and choose Keyring when asked for a passkey.")
                .font(.caption2)
                .opacity(0.8)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }

    private var storage: String {
        if !passkey.isBackupEligible {
            String(localized: "On this iPhone only")
        } else if isSyncEnabled {
            String(localized: "Synced with iCloud Keychain")
        } else {
            String(localized: "On this iPhone, synced when iCloud sync is on")
        }
    }
}

/// Renaming, recoloring, and deleting a passkey card.
struct EditPasskeyView: View {
    @Environment(AccountStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    let passkey: Passkey
    @State private var title: String
    @State private var cardColor: CardColor?
    @State private var isFavorite = false
    @State private var tags: [String] = []
    @State private var newTag = ""
    @State private var hasLoaded = false

    init(passkey: Passkey) {
        self.passkey = passkey
        _title = State(initialValue: passkey.customTitle ?? "")
        _cardColor = State(initialValue: passkey.cardColor)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField(passkey.relyingParty, text: $title)
                } header: {
                    Text("Name")
                } footer: {
                    Text("Leave empty to show the website. Renaming does not affect signing in.")
                }
                Section("Passkey") {
                    LabeledContent("Website", value: passkey.relyingParty)
                    LabeledContent("Account", value: passkey.userName)
                }
                if !store.isMetaUnavailable {
                    OrganizeSection(isFavorite: $isFavorite, tags: $tags, newTag: $newTag)
                }
                CardColorSection(selection: $cardColor, automatic: .automatic(for: passkey.relyingParty))
                DeleteCardSection(
                    label: "Delete Passkey",
                    title: String(localized: "Delete the passkey for “\(passkey.displayTitle)”?"),
                    message: Text("You will no longer be able to sign in to \(passkey.relyingParty) with this passkey. Also remove it in the website’s account settings. This cannot be undone.")
                ) {
                    store.deletePasskey(passkey.id)
                    // On failure the card and the edits stay, so it can be tried again.
                    guard store.passkeys.contains(where: { $0.id == passkey.id }) else {
                        dismiss()
                        return nil
                    }
                    // Taken from the store, so the home screen does not show it again later.
                    let error = store.lastError
                    store.lastError = nil
                    return error ?? ""
                }
            }
            .onAppear {
                guard !hasLoaded else { return }
                hasLoaded = true
                isFavorite = store.meta(for: passkey.id).isFavorite
                tags = store.meta(for: passkey.id).tags
            }
            .navigationTitle("Edit Card")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        store.updatePasskey(passkey.id, title: title.trimmed, cardColor: cardColor)
                        if !store.isMetaUnavailable {
                            store.setOrganization(isFavorite: isFavorite, tags: OrganizeSection.adding(newTag, to: tags), for: passkey.id)
                        }
                        dismiss()
                    }
                }
            }
        }
    }
}

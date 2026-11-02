import SwiftUI

/// The list AutoFill shows when the user asks Keyring for a code.
struct OneTimeCodePickerView: View {
    let accounts: [OTPAccount]
    let details: [UUID: AccountDetails]
    /// The site asking for a code, if the system said which.
    let host: String?
    let onPick: (OTPAccount, _ rememberSite: Bool) -> Void
    let onCancel: () -> Void

    @State private var query = ""
    @State private var rememberSite = true

    private func matchesHost(_ account: OTPAccount) -> Bool {
        guard let host else { return false }
        return (details[account.id]?.websites ?? []).contains { Website.matches(host: host, site: $0) }
    }

    private var filtered: [OTPAccount] {
        let words = query.trimmingCharacters(in: .whitespaces)
        guard !words.isEmpty else { return accounts }
        return accounts.filter {
            $0.issuer.localizedStandardContains(words) || $0.accountName.localizedStandardContains(words)
        }
    }

    var body: some View {
        NavigationStack {
            List {
                let suggested = filtered.filter(matchesHost)
                if !suggested.isEmpty {
                    Section("Suggested") {
                        ForEach(suggested) { row($0, isSuggested: true) }
                    }
                }
                Section(suggested.isEmpty ? "Accounts" : "Other Accounts") {
                    ForEach(filtered.filter { !matchesHost($0) }) { row($0, isSuggested: false) }
                }
                if let host, Website.normalized(host) != nil {
                    Section {
                        Toggle("Suggest for \(host) Next Time", isOn: $rememberSite)
                    } footer: {
                        Text("Adds this site to the card you choose, so its code appears above the keyboard.")
                    }
                }
            }
            .overlay {
                if accounts.isEmpty {
                    ContentUnavailableView("No Accounts", systemImage: "key", description: Text("Add accounts in the Keyring app first."))
                }
            }
            .searchable(text: $query, placement: .navigationBarDrawer(displayMode: .always))
            .navigationTitle("Choose a Code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onCancel)
                }
            }
        }
    }

    private func row(_ account: OTPAccount, isSuggested: Bool) -> some View {
        Button {
            onPick(account, rememberSite && !isSuggested)
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(account.displayTitle)
                        .foregroundStyle(.primary)
                    if let subtitle = account.displaySubtitle {
                        Text(subtitle)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if account.kind.isTimeBased {
                    TimelineView(.periodic(from: .now, by: 1)) { timeline in
                        Text(TOTPGenerator.formatted(TOTPGenerator.code(for: account, at: timeline.date)?.value ?? ""))
                            .font(.body.monospaced())
                            .foregroundStyle(.secondary)
                    }
                } else {
                    // Making one uses it up, so it is made only once picked.
                    Text("Next code")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .contentShape(.rect)
        }
        .buttonStyle(.plain)
    }
}

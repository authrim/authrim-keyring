import SwiftUI

struct EditAccountView: View {
    @Environment(AccountStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    let account: OTPAccount
    @State private var issuer: String
    @State private var accountName: String
    @State private var cardColor: CardColor?

    init(account: OTPAccount) {
        self.account = account
        _issuer = State(initialValue: account.issuer)
        _accountName = State(initialValue: account.accountName)
        _cardColor = State(initialValue: account.cardColor)
    }

    /// The account as it would look after saving, for the preview.
    private var edited: OTPAccount {
        var copy = account
        copy.issuer = issuer.trimmed
        copy.accountName = accountName.trimmed
        copy.cardColor = cardColor
        return copy
    }

    private var canSave: Bool {
        !issuer.trimmed.isEmpty || !accountName.trimmed.isEmpty
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    KeyringCardView(
                        appearance: CardAppearance(base: edited.effectiveCardColor),
                        title: edited.displayTitle,
                        subtitle: edited.displaySubtitle,
                        kind: "2FA",
                        isExpanded: false,
                        isDetailVisible: false,
                        onToggle: {}
                    ) { EmptyView() }
                    .allowsHitTesting(false)
                    .accessibilityHidden(true)
                    .listRowInsets(EdgeInsets())
                    .listRowBackground(Color.clear)
                }
                Section {
                    TextField("Service", text: $issuer)
                        .textContentType(.organizationName)
                    TextField("Account", text: $accountName)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                } footer: {
                    Text("Changing the name does not affect the codes.")
                }
                CardColorSection(
                    selection: $cardColor,
                    automatic: .automatic(for: edited.displayTitle)
                )
                AccountParametersSection(account: account)
            }
            .navigationTitle("Edit Card")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        store.update(account.id, issuer: issuer.trimmed, accountName: accountName.trimmed, cardColor: cardColor)
                        dismiss()
                    }
                    .disabled(!canSave)
                }
            }
        }
    }
}

/// Read-only summary of how an account's codes are generated.
struct AccountParametersSection: View {
    let account: OTPAccount

    var body: some View {
        Section("Code Settings") {
            LabeledContent("Type", value: "TOTP")
            LabeledContent("Algorithm", value: account.algorithm.rawValue)
            LabeledContent("Digits", value: "\(account.digits)")
            LabeledContent("Period") {
                Text("\(account.period) seconds")
            }
        }
    }
}

extension String {
    var trimmed: String { trimmingCharacters(in: .whitespacesAndNewlines) }
}

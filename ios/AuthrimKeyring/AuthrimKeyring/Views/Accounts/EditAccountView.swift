import SwiftUI

struct EditAccountView: View {
    @Environment(AccountStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    let account: OTPAccount
    @State private var issuer: String
    @State private var accountName: String

    init(account: OTPAccount) {
        self.account = account
        _issuer = State(initialValue: account.issuer)
        _accountName = State(initialValue: account.accountName)
    }

    private var canSave: Bool {
        !issuer.trimmed.isEmpty || !accountName.trimmed.isEmpty
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Service", text: $issuer)
                        .textContentType(.organizationName)
                    TextField("Account", text: $accountName)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                } footer: {
                    Text("Changing the name does not affect the codes.")
                }
                AccountParametersSection(account: account)
            }
            .navigationTitle("Edit Account")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        store.rename(account.id, issuer: issuer.trimmed, accountName: accountName.trimmed)
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

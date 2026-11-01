import SwiftUI

/// Lets the user review and name a scanned account before it is saved.
struct ConfirmAccountView: View {
    @Environment(AccountStore.self) private var store

    let candidate: OTPAccount
    let onSaved: () -> Void

    @State private var issuer: String
    @State private var accountName: String

    init(candidate: OTPAccount, onSaved: @escaping () -> Void) {
        self.candidate = candidate
        self.onSaved = onSaved
        _issuer = State(initialValue: candidate.issuer)
        _accountName = State(initialValue: candidate.accountName)
    }

    private var canSave: Bool {
        !issuer.trimmed.isEmpty || !accountName.trimmed.isEmpty
    }

    var body: some View {
        Form {
            if store.containsDuplicate(of: candidate) {
                Section {
                    Label("This account has already been added.", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
            }
            Section {
                TextField("Service", text: $issuer)
                    .textContentType(.organizationName)
                TextField("Account", text: $accountName)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
            } header: {
                Text("Name")
            } footer: {
                Text("Check that the service matches the site where you are turning on two-factor authentication.")
            }
            AccountParametersSection(account: candidate)
        }
        .navigationTitle("Confirm Account")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Add") { save() }
                    .disabled(!canSave)
            }
        }
    }

    private func save() {
        var account = candidate
        account.issuer = issuer.trimmed
        account.accountName = accountName.trimmed
        if store.add(account) { onSaved() }
    }
}

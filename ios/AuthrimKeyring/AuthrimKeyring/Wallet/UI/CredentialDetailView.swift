import SwiftUI

/// Everything about one credential, and the way to remove it.
struct CredentialDetailView: View {
    @Environment(WalletModel.self) private var wallet
    @Environment(\.dismiss) private var dismiss
    let credential: StoredCredential
    @State private var isConfirmingRemoval = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Issuer") {
                    IssuerLabel(issuer: credential.issuer, displayName: credential.issuerDisplayName)
                }
                Section("Credential") {
                    LabeledContent("Name", value: credential.credentialName)
                    LabeledContent("Type", value: credential.vct)
                }
                Section("Claims") {
                    if credential.claims.isEmpty {
                        Text("No claims").foregroundStyle(.secondary)
                    }
                    ForEach(credential.sortedClaims, id: \.name) { claim in
                        LabeledContent(claim.name, value: claim.value)
                    }
                }
                Section("Validity") {
                    LabeledContent("Issued") {
                        Text(credential.issuedAt, format: .dateTime.year().month().day())
                    }
                    if let expiresAt = credential.expiresAt {
                        LabeledContent("Expires") {
                            Text(expiresAt, format: .dateTime.year().month().day())
                        }
                        if credential.isExpired {
                            Label("Expired", systemImage: "exclamationmark.circle.fill")
                                .foregroundStyle(.red)
                        }
                    }
                }
                Section {
                    ConfirmationCodeText(code: credential.confirmationCode, font: .system(.title, design: .monospaced, weight: .semibold))
                        .frame(maxWidth: .infinity)
                } header: {
                    Text("Confirmation Code")
                } footer: {
                    Text("The admin console shows the same code for this credential.")
                }
                Section {
                    Button("Remove from Keyring", role: .destructive) { isConfirmingRemoval = true }
                }
            }
            .navigationTitle(credential.credentialName)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .confirmationDialog(
                "Remove “\(credential.credentialName)”?",
                isPresented: $isConfirmingRemoval,
                titleVisibility: .visible
            ) {
                Button("Remove", role: .destructive) {
                    if wallet.remove(credential) { dismiss() }
                }
            } message: {
                Text("This device’s key for the credential is deleted, so it can no longer be presented. Also revoke it in the admin console. This cannot be undone.")
            }
            .alert("Something went wrong", isPresented: hasError) {
                Button("OK") { wallet.lastError = nil }
            } message: {
                Text(wallet.lastError ?? "")
            }
        }
    }

    private var hasError: Binding<Bool> {
        Binding(get: { wallet.lastError != nil }, set: { if !$0 { wallet.lastError = nil } })
    }
}

#if DEBUG
#Preview {
    CredentialDetailView(credential: .previewSample)
        .environment(WalletModel.preview(credentials: [.previewSample]))
}
#endif

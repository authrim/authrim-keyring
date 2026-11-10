import SwiftUI

/// Everything about one credential, and the way to remove it.
struct CredentialDetailView: View {
    @Environment(WalletModel.self) private var wallet
    @Environment(\.dismiss) private var dismiss
    let credential: StoredCredential
    @State private var isConfirmingRemoval = false

    var body: some View {
        // The stored copy, so a confirmation made here shows at once.
        let credential = wallet.credentials.first { $0.id == self.credential.id } ?? self.credential
        Form {
            // The card itself first, to show to someone in person.
            Section {
                CredentialFaceView(credential: credential, trust: wallet.trust(for: credential.issuer))
                    .frame(maxWidth: .infinity)
                    .listRowInsets(EdgeInsets(top: 8, leading: 0, bottom: 8, trailing: 0))
                    .listRowBackground(Color.clear)
            }
            Section("Issuer") {
                IssuerLabel(issuer: credential.issuer, displayName: credential.issuerDisplayName,
                            trust: wallet.trust(for: credential.issuer),
                            displayDirection: credential.issuerDisplayDirection)
            }
            Section("Credential") {
                LabeledContent("Name", value: (credential.credentialDisplay?.nameDirection ?? .auto)
                    .isolate(credential.credentialName))
                LabeledContent("Type", value: credential.vct)
            }
            Section("Claims") {
                if credential.claims.isEmpty {
                    Text("No claims").foregroundStyle(.secondary)
                }
                if let rows = credential.credentialDisplay?.claimDisplays, !rows.isEmpty {
                    ForEach(rows) { claim in
                        VStack(alignment: .leading, spacing: 3) {
                            LabeledContent(claim.direction.isolate(claim.label),
                                           value: CredentialTextDirection.auto.isolate(claim.value))
                            if let description = claim.description {
                                Text(claim.direction.isolate(description))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                } else {
                    ForEach(credential.sortedClaims, id: \.name) { claim in
                        LabeledContent(claim.name, value: claim.value)
                    }
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
                if credential.confirmedAt == nil {
                    Button("Codes Match") { wallet.confirm(credential) }
                        .frame(maxWidth: .infinity)
                }
            } header: {
                Text("Confirmation Code")
            } footer: {
                Text("If your issuer shows a confirmation code, compare it with this code before tapping Codes Match.")
            }
            Section {
                Button("Remove from Keyring", role: .destructive) { isConfirmingRemoval = true }
            }
        }
        .navigationTitle(credential.credentialName)
        .navigationBarTitleDisplayMode(.inline)
        .confirmationDialog(
            "Remove “\(credential.credentialName)”?",
            isPresented: $isConfirmingRemoval,
            titleVisibility: .visible
        ) {
            Button("Remove", role: .destructive) {
                if wallet.remove(credential) { dismiss() }
            }
        } message: {
            if !wallet.deletesKey(credential) {
                Text("Another credential on this iPhone uses the same key, so the key stays. Also revoke this credential with its issuer.")
            } else if credential.secondFactorRegisteredAt != nil {
                Text("This credential’s key is your second factor in the admin console. Once it is deleted, you cannot approve important operations with Keyring until you register a new one. This cannot be undone.")
            } else {
                Text("This device’s key for the credential is deleted, so it can no longer be presented. Also revoke it with its issuer. This cannot be undone.")
            }
        }
        .alert("Something went wrong", isPresented: hasError) {
            Button("OK") { wallet.lastError = nil }
        } message: {
            Text(wallet.lastError ?? "")
        }
    }

    private var hasError: Binding<Bool> {
        Binding(get: { wallet.lastError != nil }, set: { if !$0 { wallet.lastError = nil } })
    }
}

#if DEBUG
#Preview {
    NavigationStack {
        CredentialDetailView(credential: .previewSample)
    }
    .environment(WalletModel.preview(credentials: [.previewSample]))
}
#endif

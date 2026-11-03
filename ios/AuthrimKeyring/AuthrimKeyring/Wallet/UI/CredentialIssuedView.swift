import SwiftUI

/// Shown after the credential is stored: the code to compare with the admin console. Saying the codes
/// match is what lets Keyring show the issuer as confirmed by the user.
struct CredentialIssuedView: View {
    @Environment(WalletModel.self) private var wallet
    let credential: StoredCredential
    let onDone: () -> Void

    var body: some View {
        ScrollView {
            VStack(spacing: 20) {
                Image(systemName: "checkmark.seal.fill")
                    .font(.system(size: 56))
                    .foregroundStyle(.green)
                    .accessibilityHidden(true)
                VStack(spacing: 6) {
                    Text("Credential Received")
                        .font(.title2.bold())
                    Text(credential.credentialName)
                        .font(.headline)
                    Text(credential.issuer.walletHost)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .multilineTextAlignment(.center)

                VStack(spacing: 12) {
                    Text("Confirmation Code")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.secondary)
                    ConfirmationCodeText(code: credential.confirmationCode)
                    Text("Check that the admin console shows the same code.")
                        .font(.callout)
                        .multilineTextAlignment(.center)
                    // The code only proves the console saw this key, so the console's own address matters too.
                    Text("Use the console you signed in to yourself at \(credential.issuer.walletHost). If the codes match, Keyring shows this issuer as confirmed by you.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .padding()
                .frame(maxWidth: .infinity)
                .background(.fill.tertiary, in: .rect(cornerRadius: 16))

                Text("If the code differs, or the console shows no credential, someone else may have used the offer. Revoke the credential in the admin console.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding()
        }
        .safeAreaInset(edge: .bottom) {
            VStack(spacing: 8) {
                Button {
                    if wallet.confirm(credential) { onDone() }
                } label: {
                    Text("Codes Match").frame(maxWidth: .infinity, minHeight: 32)
                }
                .buttonStyle(.borderedProminent)
                // Leaves the issuer unconfirmed; the codes can still be compared from the credential's details.
                Button(action: onDone) {
                    Text("Check Later").frame(maxWidth: .infinity, minHeight: 32)
                }
            }
            .controlSize(.large)
            .padding()
            .background(.bar)
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

/// A failed step: what happened and whether trying again can help.
struct CredentialFailureView: View {
    let error: WalletError
    let onRetry: () -> Void
    let onClose: () -> Void

    var body: some View {
        ContentUnavailableView {
            Label {
                Text(error.title)
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill")
            }
        } description: {
            VStack(spacing: 8) {
                Text(error.message)
                if !error.canRetry {
                    Text("A new offer is needed.")
                        .fontWeight(.semibold)
                }
                if let detail = error.detail {
                    Text(detail)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        } actions: {
            if error.canRetry {
                Button("Try Again", action: onRetry)
                    .buttonStyle(.borderedProminent)
            }
            Button("Close", action: onClose)
        }
    }
}

#if DEBUG
#Preview("Issued") {
    CredentialIssuedView(credential: .previewSample, onDone: {})
        .environment(WalletModel.preview(credentials: [.previewSample]))
}

#Preview("Failure") {
    CredentialFailureView(error: .offerRejected, onRetry: {}, onClose: {})
}
#endif

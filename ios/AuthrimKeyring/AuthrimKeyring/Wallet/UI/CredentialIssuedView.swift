import SwiftUI

/// Shown after the credential is stored: the code to compare with the admin console.
struct CredentialIssuedView: View {
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
            Button(action: onDone) {
                Text("Done").frame(maxWidth: .infinity, minHeight: 32)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .padding()
            .background(.bar)
        }
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
}

#Preview("Failure") {
    CredentialFailureView(error: .offerRejected, onRetry: {}, onClose: {})
}
#endif

import SwiftUI

/// Shown after credentials are stored. For a single credential, the holder key code can be compared
/// with the issuing service when it provides one; matching codes confirm the issuer to the user.
struct CredentialIssuedView: View {
    @Environment(WalletModel.self) private var wallet
    let credentials: [StoredCredential]
    let partialFailure: String?
    let onDone: () -> Void

    init(credential: StoredCredential, onDone: @escaping () -> Void) {
        self.init(credentials: [credential], partialFailure: nil, onDone: onDone)
    }

    init(credentials: [StoredCredential], partialFailure: String?, onDone: @escaping () -> Void) {
        self.credentials = credentials
        self.partialFailure = partialFailure
        self.onDone = onDone
    }

    var body: some View {
        Group {
            if credentials.count == 1 && partialFailure == nil {
                singleReceipt
            } else {
                multipleReceipt
            }
        }
    }

    private var credential: StoredCredential { credentials[0] }

    private var singleReceipt: some View {
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
                    Text("Compare this code with the issuing service if it shows one.")
                        .font(.callout)
                        .multilineTextAlignment(.center)
                    // The code only proves the issuer saw this key, so the service address matters too.
                    Text("Only confirm a matching code shown by the service you opened yourself for \(credential.issuer.walletHost). Keyring will mark this issuer as confirmed by you.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                .padding()
                .frame(maxWidth: .infinity)
                .background(.fill.tertiary, in: .rect(cornerRadius: 16))

                Text("If the code differs, do not confirm it. Contact the issuer to check or revoke the credential.")
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

    private var multipleReceipt: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HStack(spacing: 12) {
                    Image(systemName: partialFailure == nil ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                        .font(.system(size: 40))
                        .foregroundStyle(partialFailure == nil ? .green : .orange)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 4) {
                        if partialFailure == nil {
                            Text("Credentials Received").font(.title2.bold())
                        } else {
                            Text("Some Credentials Received").font(.title2.bold())
                        }
                        Text("\(credentials.count) saved from \(credential.issuer.walletHost)")
                            .foregroundStyle(.secondary)
                    }
                }

                if let partialFailure {
                    Text(partialFailure)
                        .font(.callout)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding()
                        .background(.orange.opacity(0.12), in: .rect(cornerRadius: 12))
                }

                ForEach(credentials) { stored in
                    VStack(alignment: .leading, spacing: 4) {
                        Text(stored.credentialName).font(.headline)
                        Text(stored.issuer.walletHost).font(.subheadline).foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
                    .background(.fill.tertiary, in: .rect(cornerRadius: 12))
                }

                Text("You can review each credential and its key confirmation code in your wallet.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            .padding()
        }
        .safeAreaInset(edge: .bottom) {
            Button("Done", action: onDone)
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .frame(maxWidth: .infinity)
                .padding()
                .background(.bar)
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

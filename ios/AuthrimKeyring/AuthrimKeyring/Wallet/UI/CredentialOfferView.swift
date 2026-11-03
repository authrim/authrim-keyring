import SwiftUI

/// Shows a credential offer and runs the receiving of it. Pushed inside the add flow or wrapped in
/// `CredentialOfferSheet` when the offer came from a link.
struct CredentialOfferView: View {
    @Environment(WalletModel.self) private var wallet
    @State private var flow: CredentialOfferFlow
    let showsCancel: Bool
    let onClose: () -> Void

    init(offer: String, showsCancel: Bool = false, onClose: @escaping () -> Void) {
        _flow = State(initialValue: CredentialOfferFlow(offer: offer))
        self.showsCancel = showsCancel
        self.onClose = onClose
    }

    var body: some View {
        content
            .navigationTitle("Receive Credential")
            .navigationBarTitleDisplayMode(.inline)
            // The key and the one-time code are in use; leaving now would waste the offer.
            .navigationBarBackButtonHidden(flow.isBusy || flow.isIssued)
            .interactiveDismissDisabled(flow.isBusy)
            .toolbar {
                if showsCancel && !flow.isBusy && !flow.isIssued {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel", action: onClose)
                    }
                }
            }
            .task { await flow.start(using: wallet) }
    }

    @ViewBuilder
    private var content: some View {
        switch flow.phase {
        case .loading:
            ProgressView("Checking the offer…")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .ready(let preview):
            CredentialOfferForm(flow: flow, preview: preview, isIssuing: false)
        case .issuing(let preview):
            CredentialOfferForm(flow: flow, preview: preview, isIssuing: true)
        case .issued(let credential):
            CredentialIssuedView(credential: credential, onDone: onClose)
        case .failed(let error, _):
            CredentialFailureView(error: error, onRetry: { Task { await flow.retry(using: wallet) } }, onClose: onClose)
        }
    }
}

/// The offer's details, the transaction code field and the Receive button.
private struct CredentialOfferForm: View {
    @Environment(WalletModel.self) private var wallet
    @Bindable var flow: CredentialOfferFlow
    let preview: CredentialOfferPreview
    let isIssuing: Bool
    @FocusState private var isCodeFocused: Bool

    var body: some View {
        let trust = wallet.trust(for: preview.issuer)
        Form {
            Section("Issuer") {
                IssuerLabel(issuer: preview.issuer, displayName: preview.issuerDisplayName, trust: trust)
            }
            Section {
                Text(preview.credentialName)
                    .font(.headline)
                ForEach(preview.claimNames, id: \.self) { name in
                    Label(name, systemImage: "checkmark.circle")
                        .font(.subheadline)
                }
            } header: {
                Text("Credential")
            } footer: {
                switch trust {
                case .verified: EmptyView()
                case .confirmedByUser:
                    Text("You confirmed this issuer when you compared a confirmation code. Keyring itself does not vouch for who runs it.")
                case .unconfirmed:
                    Text("Only receive a credential from an issuer you recognize. Keyring cannot confirm who runs it.")
                }
            }
            if let requirement = preview.transactionCode {
                codeSection(requirement)
            }
            Section {
            } footer: {
                Text("Keyring creates a key for this credential in the Secure Enclave of this device. You will be asked for Face ID, Touch ID or your passcode.")
            }
        }
        .disabled(isIssuing)
        .scrollDismissesKeyboard(.interactively)
        .safeAreaInset(edge: .bottom) {
            Button {
                isCodeFocused = false
                Task { await flow.receive(preview, using: wallet) }
            } label: {
                if isIssuing {
                    ProgressView().frame(maxWidth: .infinity, minHeight: 32)
                } else {
                    Text("Receive").frame(maxWidth: .infinity, minHeight: 32)
                }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(isIssuing || !flow.canReceive(preview))
            .padding()
            .background(.bar)
        }
        .accessibilityElement(children: .contain)
    }

    private func codeSection(_ requirement: TransactionCodeRequirement) -> some View {
        Section {
            TextField("Transaction code", text: $flow.transactionCode)
                .font(.title3.monospaced())
                .keyboardType(requirement.numeric ? .numberPad : .asciiCapable)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .textContentType(.oneTimeCode)
                .focused($isCodeFocused)
                .onChange(of: flow.transactionCode) { _, text in
                    var cleaned = requirement.numeric ? text.filter(\.isASCIIDigit) : text
                    if let length = requirement.length { cleaned = String(cleaned.prefix(length)) }
                    if cleaned != text { flow.transactionCode = cleaned }
                }
        } header: {
            Text("Transaction Code")
        } footer: {
            VStack(alignment: .leading, spacing: 4) {
                if let length = requirement.length {
                    Text(requirement.numeric ? "Enter the \(length)-digit code shown in the admin console." : "Enter the \(length)-character code shown in the admin console.")
                } else {
                    Text("Enter the code shown in the admin console.")
                }
                // Text the issuer supplied; shown as given.
                if let description = requirement.description, !description.isEmpty {
                    Text(description)
                }
            }
        }
    }
}

private extension Character {
    var isASCIIDigit: Bool { isASCII && isNumber }
}

/// The sheet used when an offer is opened from a link.
struct CredentialOfferSheet: View {
    @Environment(\.dismiss) private var dismiss
    let offer: String

    var body: some View {
        NavigationStack {
            CredentialOfferView(offer: offer, showsCancel: true) { dismiss() }
        }
    }
}

#if DEBUG
#Preview("Offer") {
    CredentialOfferSheet(offer: "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fid.example.com%2Foffer%2F1")
        .environment(WalletModel.preview())
}

#Preview("Rejected") {
    CredentialOfferSheet(offer: "openid-credential-offer://rejected")
        .environment(WalletModel.preview(issue: .failure(.offerRejected)))
}
#endif

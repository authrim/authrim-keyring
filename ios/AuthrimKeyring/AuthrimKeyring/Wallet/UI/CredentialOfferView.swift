import SwiftUI

/// Shows a credential offer and runs the receiving of it. Pushed inside the add flow or wrapped in
/// `CredentialOfferSheet` when the offer came from a link.
struct CredentialOfferView: View {
    @Environment(WalletModel.self) private var wallet
    @State private var flow: CredentialOfferFlow
    let showsCancel: Bool
    let onClose: () -> Void

    init(flow: CredentialOfferFlow, showsCancel: Bool = false, onClose: @escaping () -> Void) {
        _flow = State(initialValue: flow)
        self.showsCancel = showsCancel
        self.onClose = onClose
    }

    init(offer: String, showsCancel: Bool = false, onClose: @escaping () -> Void) {
        self.init(flow: CredentialOfferFlow(offer: offer), showsCancel: showsCancel, onClose: onClose)
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
        case .issued(let credentials, let partialFailure):
            CredentialIssuedView(credentials: credentials, partialFailure: partialFailure, onDone: onClose)
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
                if !WalletHTTP.sameOrigin(preview.authorizationServer, preview.issuer) {
                    LabeledContent("Authorization server", value: preview.authorizationServer.walletHost)
                }
            }
            Section {
                ForEach(preview.credentials) { credential in
                    credentialRow(credential)
                }
            } header: {
                if preview.credentials.count == 1 {
                    Text("Credential")
                } else {
                    Text("Credentials to Receive")
                }
            } footer: {
                VStack(alignment: .leading, spacing: 6) {
                    if preview.credentials.count > 1 {
                        Text("\(flow.selectedConfigurationIds.count) selected. Keyring sends a separate request for each credential.")
                    }
                    switch trust {
                    case .verified: EmptyView()
                    case .confirmedByUser:
                        Text("You confirmed this issuer when you compared a confirmation code. Keyring itself does not vouch for who runs it.")
                    case .unconfirmed:
                        Text("Only receive a credential from an issuer you recognize. Keyring cannot confirm who runs it.")
                    }
                    if preview.issuer.absoluteString == "https://issuer.eudiw.dev" {
                        Text("EUDI test issuer: the public test attestation service does not verify this iPhone's Secure Enclave properties. Use this offer for interoperability testing only.")
                    }
                }
            }
            if let requirement = preview.transactionCode {
                codeSection(requirement)
            }
            Section {
            } footer: {
                if preview.credentials.contains(where: { flow.selectedConfigurationIds.contains($0.id) && $0.renewsCredential }) {
                    Text("For a renewal, Keyring reuses the key already on this device so your second factor keeps working. New credentials receive separate Secure Enclave keys. You will be asked for Face ID, Touch ID or your passcode.")
                } else {
                    Text("Keyring creates a separate Secure Enclave key for each selected credential. You will be asked for Face ID, Touch ID or your passcode.")
                }
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
                    Group {
                        if preview.authorizationRequired {
                            Text("Continue to Issuer")
                        } else {
                            Text("Receive")
                        }
                    }
                    .frame(maxWidth: .infinity, minHeight: 32)
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

    @ViewBuilder
    private func credentialRow(_ credential: OfferedCredential) -> some View {
        if preview.credentials.count == 1 {
            VStack(alignment: .leading, spacing: 6) {
                Text(credential.name).font(.headline)
                ForEach(credential.claimNames.indices, id: \.self) { index in
                    Label(credential.claimNames[index], systemImage: "checkmark.circle")
                        .font(.subheadline)
                }
            }
        } else {
            Button {
                flow.toggleSelection(credential.id)
            } label: {
                HStack(alignment: .top, spacing: 12) {
                    Image(systemName: flow.selectedConfigurationIds.contains(credential.id)
                          ? "checkmark.circle.fill" : "circle")
                        .foregroundStyle(flow.selectedConfigurationIds.contains(credential.id)
                                         ? Color.accentColor : Color.secondary)
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 6) {
                        Text(credential.name).font(.headline)
                        ForEach(credential.claimNames.indices, id: \.self) { index in
                            Text(credential.claimNames[index]).font(.subheadline).foregroundStyle(.secondary)
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .accessibilityLabel(([credential.name] + credential.claimNames).joined(separator: ", "))
            .accessibilityValue(flow.selectedConfigurationIds.contains(credential.id)
                                ? Text("Selected") : Text("Not selected"))
            .accessibilityHint("Double tap to change selection")
        }
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
                    if requirement.numeric {
                        Text("Enter the \(length)-digit code supplied with this offer.")
                    } else {
                        Text("Enter the \(length)-character code supplied with this offer.")
                    }
                } else {
                    Text("Enter the code supplied with this offer.")
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
    let flow: CredentialOfferFlow

    init(flow: CredentialOfferFlow) {
        self.flow = flow
    }

    init(offer: String) {
        flow = CredentialOfferFlow(offer: offer)
    }

    var body: some View {
        NavigationStack {
            CredentialOfferView(flow: flow, showsCancel: true) { dismiss() }
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

import SwiftUI

/// Answers a request from the Authrim admin console with the admin credential. Pushed inside the
/// add flow (scanner) or wrapped in `PresentationSheet` when the request came from a link.
struct PresentationView: View {
    @Environment(WalletModel.self) private var wallet
    @State private var flow: PresentationFlow
    let showsCancel: Bool
    let onClose: () -> Void

    init(link: String, showsCancel: Bool = false, onClose: @escaping () -> Void) {
        _flow = State(initialValue: PresentationFlow(link: link))
        self.showsCancel = showsCancel
        self.onClose = onClose
    }

    var body: some View {
        content
            .navigationTitle("Admin Console Request")
            .navigationBarTitleDisplayMode(.inline)
            .navigationBarBackButtonHidden(flow.isBusy || flow.isDone)
            .interactiveDismissDisabled(flow.isBusy)
            .toolbar {
                if showsCancel && !flow.isBusy && !flow.isDone {
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
            ProgressView("Checking the request…")
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .ready(let request):
            PresentationForm(flow: flow, request: request, isSending: false)
        case .sending(let request):
            PresentationForm(flow: flow, request: request, isSending: true)
        case .done:
            PresentationDoneView(onDone: onClose)
        case .failed(let error, _):
            PresentationFailureView(
                error: error, onRetry: { Task { await flow.retry(using: wallet) } }, onClose: onClose)
        }
    }
}

/// Who asks, what for, the number field and the Approve button.
private struct PresentationForm: View {
    @Environment(WalletModel.self) private var wallet
    @Bindable var flow: PresentationFlow
    let request: PresentationRequest
    let isSending: Bool
    @FocusState private var isCodeFocused: Bool

    var body: some View {
        Form {
            Section {
                LabeledContent("Server", value: request.verifierHost)
                if !request.tenant.isEmpty && request.tenant != request.verifierHost {
                    LabeledContent("Tenant", value: request.tenant)
                }
            } header: {
                Text("Request From")
            } footer: {
                Text("Keyring answers only the server that issued your admin credential.")
            }
            Section("What You Approve") {
                switch request.purpose {
                case .stepUp:
                    Label("An important operation in the admin console", systemImage: "checkmark.shield")
                case .enroll:
                    Label("Use this credential as a second factor", systemImage: "key.viewfinder")
                }
                LabeledContent("Credential", value: request.credential.credentialName)
            }
            Section {
                TextField("Two digits", text: $flow.matchCode)
                    .font(.title.monospacedDigit())
                    .keyboardType(.numberPad)
                    .textContentType(.oneTimeCode)
                    .focused($isCodeFocused)
                    .onChange(of: flow.matchCode) { _, _ in flow.normalizeCode() }
                    .accessibilityHint("Enter the two digits shown in the admin console.")
            } header: {
                Text("Number in the Admin Console")
            } footer: {
                Text("Type the number your admin console shows right now. Never type a number someone else tells you: they may be trying to use your credential.")
            }
            Section {
            } footer: {
                Text("Only your admin credential’s identity is sent, signed with its key on this iPhone. You will be asked for Face ID or your passcode.")
            }
        }
        .disabled(isSending)
        .scrollDismissesKeyboard(.interactively)
        .onAppear { isCodeFocused = true }
        .safeAreaInset(edge: .bottom) {
            Button {
                isCodeFocused = false
                Task { await flow.approve(request, using: wallet) }
            } label: {
                if isSending {
                    ProgressView().frame(maxWidth: .infinity, minHeight: 32)
                } else {
                    Text("Approve").frame(maxWidth: .infinity, minHeight: 32)
                }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(isSending || !flow.canApprove)
            .padding()
            .background(.bar)
        }
    }
}

private struct PresentationDoneView: View {
    let onDone: () -> Void

    var body: some View {
        ContentUnavailableView {
            Label("Approved", systemImage: "checkmark.circle.fill")
        } description: {
            Text("Go back to the admin console. It continues on its own.")
        } actions: {
            Button("Done", action: onDone)
                .buttonStyle(.borderedProminent)
        }
    }
}

private struct PresentationFailureView: View {
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

/// The sheet used when a request is opened from a link.
struct PresentationSheet: View {
    @Environment(\.dismiss) private var dismiss
    let link: String

    var body: some View {
        NavigationStack {
            PresentationView(link: link, showsCancel: true) { dismiss() }
        }
    }
}

#if DEBUG
#Preview("Request") {
    PresentationSheet(link: "openid4vp://?client_id=x&request_uri=https%3A%2F%2Fid.example.com%2Fr")
        .environment(WalletModel.preview(credentials: [.previewSample]))
}
#endif

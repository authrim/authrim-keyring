import SwiftUI

/// The steps of signing in to the Authrim admin console with the admin credential: check the
/// request, show who asks, approve with Face ID, send, and go back to the console.
@MainActor
@Observable
final class HAIPLoginFlow {
    enum Phase {
        case loading
        case ready(HAIPLoginRequest)
        case sending(HAIPLoginRequest)
        case done(URL)
        case failed(WalletError, request: HAIPLoginRequest?)
    }

    let link: String
    private(set) var phase = Phase.loading
    private var hasStarted = false

    init(link: String) { self.link = link }

    var isBusy: Bool {
        switch phase {
        case .loading, .sending: true
        default: false
        }
    }

    func start(using wallet: WalletModel) async {
        guard !hasStarted else { return }
        hasStarted = true
        await load(using: wallet)
    }

    private func load(using wallet: WalletModel) async {
        phase = .loading
        guard let login = wallet.login else {
            phase = .failed(.unsupportedIssuerCertificateTrust, request: nil)
            return
        }
        do {
            phase = .ready(try await login.preview(link: link, credentials: wallet.credentials))
        } catch {
            phase = .failed(Self.walletError(error), request: nil)
        }
    }

    func approve(_ request: HAIPLoginRequest, using wallet: WalletModel) async {
        guard case .ready = phase, let login = wallet.login else { return }
        phase = .sending(request)
        do {
            phase = .done(try await login.present(request))
        } catch {
            phase = .failed(Self.walletError(error), request: request)
        }
    }

    func retry(using wallet: WalletModel) async {
        guard case .failed(let error, let request) = phase else { return }
        if let request, error.canRetry, request.expiresAt > .now { phase = .ready(request) } else { await load(using: wallet) }
    }

    func choose(_ credential: StoredCredential) {
        guard case .ready(let request) = phase else { return }
        phase = .ready(request.answering(with: credential))
    }

    private static func walletError(_ error: Error) -> WalletError {
        (error as? WalletError) ?? .network(error.localizedDescription)
    }
}

struct HAIPLoginView: View {
    @Environment(WalletModel.self) private var wallet
    @Environment(\.openURL) private var openURL
    @State private var flow: HAIPLoginFlow
    let showsCancel: Bool
    let onClose: () -> Void

    init(link: String, showsCancel: Bool, onClose: @escaping () -> Void) {
        _flow = State(initialValue: HAIPLoginFlow(link: link))
        self.showsCancel = showsCancel
        self.onClose = onClose
    }

    var body: some View {
        content
            .navigationTitle("Sign in")
            .navigationBarTitleDisplayMode(.inline)
            .navigationBarBackButtonHidden(flow.isBusy)
            .interactiveDismissDisabled(flow.isBusy)
            .toolbar {
                if showsCancel && !flow.isBusy {
                    ToolbarItem(placement: .cancellationAction) { Button("Cancel", action: onClose) }
                }
            }
            .task { await flow.start(using: wallet) }
            .onChange(of: flow.isDone) { _, done in
                // The console completes the sign-in in the browser that started it.
                if done, case .done(let url) = flow.phase { openURL(url); onClose() }
            }
    }

    @ViewBuilder
    private var content: some View {
        switch flow.phase {
        case .loading:
            ProgressView("Checking the request…").frame(maxWidth: .infinity, maxHeight: .infinity)
        case .ready(let request):
            form(request, isSending: false)
        case .sending(let request):
            form(request, isSending: true)
        case .done:
            ProgressView("Returning to the console…").frame(maxWidth: .infinity, maxHeight: .infinity)
        case .failed(let error, _):
            VStack(spacing: 16) {
                Text(error.message).multilineTextAlignment(.center)
                if error.canRetry { Button("Try Again") { Task { await flow.retry(using: wallet) } }.buttonStyle(.borderedProminent) }
                Button("Close", action: onClose)
            }
            .padding()
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func form(_ request: HAIPLoginRequest, isSending: Bool) -> some View {
        Form {
            Section {
                LabeledContent("Server", value: request.verifierHost)
                LabeledContent("Credential", value: request.credential.confirmationCode)
                if request.candidates.count > 1 {
                    Picker("Key", selection: Binding(
                        get: { request.credential.id },
                        set: { id in if let chosen = request.candidates.first(where: { $0.id == id }) { flow.choose(chosen) } })
                    ) {
                        ForEach(request.candidates) { Text($0.confirmationCode).tag($0.id) }
                    }
                }
            } footer: {
                Text("This signs you in to the Authrim admin console in your browser. Approve only if you started this sign-in.")
            }
            Section {
                Button {
                    Task { await flow.approve(request, using: wallet) }
                } label: {
                    if isSending { ProgressView() } else { Text("Sign in").frame(maxWidth: .infinity) }
                }
                .disabled(isSending)
            }
        }
    }
}

private extension HAIPLoginFlow {
    var isDone: Bool { if case .done = phase { true } else { false } }
}

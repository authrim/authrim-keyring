import Foundation
import Observation

/// The steps of answering one request from the admin console: check it, show what it is for, take
/// the number from the console, sign with Face ID, send.
@MainActor
@Observable
final class PresentationFlow {
    enum Phase {
        case loading
        case ready(PresentationRequest)
        case sending(PresentationRequest)
        case done(PresentationRequest)
        case failed(WalletError, request: PresentationRequest?)
    }

    let link: String
    private(set) var phase = Phase.loading
    /// The two digits the admin console shows.
    var matchCode = ""
    private var hasStarted = false

    init(link: String) {
        self.link = link
    }

    var isBusy: Bool {
        switch phase {
        case .loading, .sending: true
        default: false
        }
    }

    var isDone: Bool {
        if case .done = phase { true } else { false }
    }

    /// Exactly two digits.
    var canApprove: Bool {
        matchCode.count == 2 && matchCode.allSatisfy { ("0"..."9").contains($0) }
    }

    func start(using wallet: WalletModel) async {
        guard !hasStarted else { return }
        hasStarted = true
        await load(using: wallet)
    }

    private func load(using wallet: WalletModel) async {
        phase = .loading
        do {
            phase = .ready(try await wallet.presentation.preview(link: link, credentials: wallet.credentials))
        } catch {
            phase = .failed(Self.walletError(error), request: nil)
        }
    }

    func approve(_ request: PresentationRequest, using wallet: WalletModel) async {
        guard case .ready = phase, canApprove else { return }
        phase = .sending(request)
        let code = matchCode
        do {
            try await wallet.presentation.present(request, matchCode: code)
            matchCode = ""
            // The console now holds this key as a second factor (or as a recovery request's new one).
            if request.purpose == .enroll { wallet.markSecondFactor(request.credential) }
            phase = .done(request)
        } catch {
            matchCode = ""
            phase = .failed(Self.walletError(error), request: request)
        }
    }

    /// Back to the request after a failure that left it usable (Face ID cancelled, no network);
    /// otherwise a second look at the link.
    func retry(using wallet: WalletModel) async {
        guard case .failed(let error, let request) = phase else { return }
        if let request, error.canRetry, request.expiresAt > .now {
            phase = .ready(request)
        } else {
            await load(using: wallet)
        }
    }

    /// Answers with another of the request's credentials (another holder key on this device).
    func choose(_ credential: StoredCredential) {
        guard case .ready(let request) = phase else { return }
        phase = .ready(request.answering(with: credential))
    }

    /// Keeps only digits, at most two.
    func normalizeCode() {
        let digits = matchCode.filter { ("0"..."9").contains($0) }
        if digits != matchCode || digits.count > 2 { matchCode = String(digits.prefix(2)) }
    }

    private static func walletError(_ error: Error) -> WalletError {
        if let error = error as? WalletError { return error }
        return .network(error.localizedDescription)
    }
}

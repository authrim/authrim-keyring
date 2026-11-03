import Foundation
import Observation

/// The steps of receiving one credential: look at the offer, ask for it, show the result.
@MainActor
@Observable
final class CredentialOfferFlow {
    enum Phase {
        case loading
        case ready(CredentialOfferPreview)
        case issuing(CredentialOfferPreview)
        case issued(StoredCredential)
        /// `preview` is set when the failure came after the offer was shown.
        case failed(WalletError, preview: CredentialOfferPreview?)
    }

    let offer: String
    private(set) var phase = Phase.loading
    var transactionCode = ""
    private var hasStarted = false

    init(offer: String) {
        self.offer = offer
    }

    var isBusy: Bool {
        switch phase {
        case .loading, .issuing: true
        default: false
        }
    }

    var isIssued: Bool {
        if case .issued = phase { true } else { false }
    }

    func start(using wallet: WalletModel) async {
        guard !hasStarted else { return }
        hasStarted = true
        await loadPreview(using: wallet)
    }

    private func loadPreview(using wallet: WalletModel) async {
        phase = .loading
        do {
            phase = .ready(try await wallet.issuance.preview(offer: offer))
        } catch {
            phase = .failed(Self.walletError(error), preview: nil)
        }
    }

    /// Whether the code field holds something the issuer could accept.
    func canReceive(_ preview: CredentialOfferPreview) -> Bool {
        guard let requirement = preview.transactionCode else { return true }
        let code = transactionCode.trimmingCharacters(in: .whitespaces)
        if let length = requirement.length { return code.count == length }
        return !code.isEmpty
    }

    func receive(_ preview: CredentialOfferPreview, using wallet: WalletModel) async {
        guard case .ready = phase, canReceive(preview) else { return }
        phase = .issuing(preview)
        let code = preview.transactionCode == nil ? nil : transactionCode.trimmingCharacters(in: .whitespaces)
        do {
            let credential = try await wallet.issuance.issue(preview, transactionCode: code)
            transactionCode = ""
            wallet.load()
            phase = .issued(credential)
        } catch {
            phase = .failed(Self.walletError(error), preview: preview)
        }
    }

    /// Back to the offer (or a second look at it, when it never loaded).
    func retry(using wallet: WalletModel) async {
        guard case .failed(_, let preview) = phase else { return }
        if let preview {
            phase = .ready(preview)
        } else {
            await loadPreview(using: wallet)
        }
    }

    private static func walletError(_ error: Error) -> WalletError {
        if let error = error as? WalletError { return error }
        return .network(error.localizedDescription)
    }
}

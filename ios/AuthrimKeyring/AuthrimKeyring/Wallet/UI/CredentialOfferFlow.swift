import Foundation
import Observation

/// The steps of receiving the selected credentials from one offer.
@MainActor
@Observable
final class CredentialOfferFlow {
    enum Phase {
        case loading
        case ready(CredentialOfferPreview)
        case issuing(CredentialOfferPreview)
        case issued([StoredCredential], partialFailure: String?)
        /// `preview` is set when the failure came after the offer was shown.
        case failed(WalletError, preview: CredentialOfferPreview?)
    }

    let offer: String
    private(set) var phase = Phase.loading
    var transactionCode = ""
    var selectedConfigurationIds: Set<String> = []
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
            let preview = try await wallet.issuance.preview(offer: offer)
            selectedConfigurationIds = Set(preview.credentials.map(\.id))
            phase = .ready(preview)
        } catch is CancellationError {
            // A temporary sheet dismissal on app lock cancels .task. The retained flow can load
            // again when the app unlocks; no one-time code has been sent at this stage.
            hasStarted = false
            phase = .loading
        } catch {
            phase = .failed(Self.walletError(error), preview: nil)
        }
    }

    /// Whether the code field holds something the issuer could accept.
    func canReceive(_ preview: CredentialOfferPreview) -> Bool {
        guard !selectedConfigurationIds.isEmpty else { return false }
        guard let requirement = preview.transactionCode else { return true }
        let code = requirement.numeric
            ? transactionCode.trimmingCharacters(in: .whitespacesAndNewlines) : transactionCode
        if let length = requirement.length { return code.count == length }
        return !code.isEmpty
    }

    func toggleSelection(_ id: String) {
        if selectedConfigurationIds.contains(id) {
            selectedConfigurationIds.remove(id)
        } else {
            selectedConfigurationIds.insert(id)
        }
    }

    func receive(_ preview: CredentialOfferPreview, using wallet: WalletModel) async {
        guard case .ready = phase, canReceive(preview) else { return }
        phase = .issuing(preview)
        let code: String?
        if let requirement = preview.transactionCode {
            code = requirement.numeric
                ? transactionCode.trimmingCharacters(in: .whitespacesAndNewlines) : transactionCode
        } else {
            code = nil
        }
        do {
            let selected = preview.credentials.map(\.id).filter { selectedConfigurationIds.contains($0) }
            let credentials = try await wallet.issuance.issueAll(
                preview, selectedConfigurationIds: selected, transactionCode: code)
            transactionCode = ""
            wallet.load()
            phase = .issued(credentials, partialFailure: nil)
        } catch let partial as PartialIssuanceError {
            transactionCode = ""
            wallet.load()
            phase = .issued(
                partial.saved,
                partialFailure: String(localized:
                    "Could not receive \(partial.failedCredentialName). \(partial.reason) A new offer is needed for the remaining credentials."))
        } catch {
            let failure = Self.walletError(error)
            if failure == .incorrectTransactionCode { transactionCode = "" }
            phase = .failed(failure, preview: preview)
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

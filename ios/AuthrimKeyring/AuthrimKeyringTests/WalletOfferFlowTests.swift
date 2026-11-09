import Foundation
import Testing
@testable import AuthrimKeyring

@MainActor
struct WalletOfferFlowTests {
    @Test func cameraOfferFlowSurvivesLockAndClearsTransactionCode() {
        let wallet = WalletModel(issuance: PreviewIssuance(), store: MemoryStore())
        let offer = "haip-vci://credential_offer?credential_offer=%7B%7D"
        wallet.receiveCameraOffer(offer)
        let flow = wallet.incomingOfferFlow
        #expect(wallet.incomingOffer?.text == offer)
        #expect(flow?.offer == offer)
        #expect(wallet.cameraOfferWaitsForAddSheet)

        wallet.addAccountSheetDidDismiss()
        #expect(!wallet.cameraOfferWaitsForAddSheet)

        flow?.transactionCode = "12345"
        wallet.suspendIncomingOfferForBackground(removesAddAccountSheet: true)
        #expect(wallet.incomingOfferFlow === flow)
        #expect(wallet.incomingOffer?.text == offer)
        #expect(flow?.transactionCode.isEmpty == true)
        #expect(!wallet.cameraOfferWaitsForAddSheet)

        wallet.closeIncomingOffer()
        wallet.incomingOfferSheetDidDismiss()
        wallet.receiveCameraOffer(offer)
        wallet.suspendIncomingOfferForBackground(removesAddAccountSheet: true)
        #expect(!wallet.cameraOfferWaitsForAddSheet)

        wallet.closeIncomingOffer()
        wallet.incomingOfferSheetDidDismiss()
        wallet.receiveCameraOffer(offer)
        wallet.suspendIncomingOfferForBackground(removesAddAccountSheet: false)
        #expect(wallet.cameraOfferWaitsForAddSheet)

        wallet.closeIncomingOffer()
        #expect(wallet.incomingOffer == nil)
        #expect(wallet.incomingOfferFlow == nil)
    }

    @Test func incorrectTransactionCodeReturnsToSameOfferForCorrection() async throws {
        let issuance = PreviewIssuance(issue: .failure(.incorrectTransactionCode), delay: .zero)
        let wallet = WalletModel(issuance: issuance, store: MemoryStore())
        let flow = CredentialOfferFlow(offer: "haip-vci://test")
        await flow.start(using: wallet)
        guard case .ready(let preview) = flow.phase else {
            Issue.record("The offer did not become ready")
            return
        }

        flow.transactionCode = "123456"
        await flow.receive(preview, using: wallet)
        guard case .failed(let error, let failedPreview) = flow.phase else {
            Issue.record("An incorrect code was not shown")
            return
        }
        #expect(error == .incorrectTransactionCode)
        #expect(error.canRetry)
        #expect(failedPreview?.id == preview.id)
        #expect(flow.transactionCode.isEmpty)

        await flow.retry(using: wallet)
        guard case .ready(let retryPreview) = flow.phase else {
            Issue.record("The same offer was not made ready for correction")
            return
        }
        #expect(retryPreview.id == preview.id)
    }

    @Test func textTransactionCodeKeepsLeadingAndTrailingSpaces() async throws {
        let recorder = TextTransactionCodeRecorder()
        let wallet = WalletModel(
            issuance: RecordingTextCodeIssuance(recorder: recorder), store: MemoryStore())
        let flow = CredentialOfferFlow(offer: "openid-credential-offer://test")
        await flow.start(using: wallet)
        guard case .ready(let preview) = flow.phase else {
            Issue.record("The text-code offer did not become ready")
            return
        }
        flow.transactionCode = " AB "
        #expect(flow.canReceive(preview))
        await flow.receive(preview, using: wallet)
        let submitted = await recorder.value
        #expect(submitted == " AB ")
    }
}

private actor TextTransactionCodeRecorder {
    private(set) var value: String?

    func record(_ value: String?) { self.value = value }
}

private nonisolated struct RecordingTextCodeIssuance: CredentialIssuanceService {
    let recorder: TextTransactionCodeRecorder

    func preview(offer: String) async throws -> CredentialOfferPreview {
        CredentialOfferPreview(
            id: UUID(), issuer: URL(string: "https://issuer.example.com")!, issuerDisplayName: nil,
            credentialConfigurationId: "example", credentialName: "Example", claimNames: [],
            transactionCode: TransactionCodeRequirement(length: 4, numeric: false, description: nil))
    }

    func issue(_ preview: CredentialOfferPreview, transactionCode: String?) async throws -> StoredCredential {
        await recorder.record(transactionCode)
        throw WalletError.offerRejected
    }
}

import Foundation
import Testing
@testable import AuthrimKeyring

@MainActor
struct WalletIncomingOfferTests {
    @Test func newLinksWaitWhileIssuingAndOpenAfterResultDismissal() async throws {
        let wallet = WalletModel(
            issuance: PreviewIssuance(delay: .milliseconds(100)), store: MemoryStore())
        let firstLink = "haip-vci://first"
        let secondLink = "haip-vci://second"
        let thirdLink = "haip-vci://third"
        wallet.receiveOffer(firstLink)
        let firstFlow = try #require(wallet.incomingOfferFlow)
        let firstOfferID = try #require(wallet.incomingOffer?.id)
        await firstFlow.start(using: wallet)
        guard case .ready(let preview) = firstFlow.phase else {
            Issue.record("The first offer did not become ready")
            return
        }
        firstFlow.transactionCode = "123456"

        let issuance = Task { await firstFlow.receive(preview, using: wallet) }
        for _ in 0..<100 {
            if case .issuing = firstFlow.phase { break }
            await Task.yield()
        }
        guard case .issuing = firstFlow.phase else {
            Issue.record("The first offer did not start issuing")
            await issuance.value
            return
        }
        wallet.receiveOffer(secondLink)
        wallet.receiveOffer(thirdLink)
        #expect(wallet.incomingOffer?.id == firstOfferID)
        #expect(wallet.incomingOfferFlow === firstFlow)
        #expect(wallet.queuedIncomingOfferCount == 2)

        await issuance.value
        #expect(firstFlow.isIssued)
        // A temporary sheet dismissal during app lock must not replace the result.
        wallet.incomingOfferSheetDidDismiss()
        #expect(wallet.incomingOffer?.id == firstOfferID)
        #expect(wallet.incomingOfferFlow === firstFlow)

        wallet.closeIncomingOffer()
        wallet.incomingOfferSheetDidDismiss()
        #expect(wallet.incomingOffer?.text == secondLink)
        #expect(wallet.incomingOfferFlow?.offer == secondLink)
        #expect(wallet.queuedIncomingOfferCount == 1)

        wallet.closeIncomingOffer()
        wallet.incomingOfferSheetDidDismiss()
        #expect(wallet.incomingOffer?.text == thirdLink)
        #expect(wallet.incomingOfferFlow?.offer == thirdLink)
        #expect(wallet.queuedIncomingOfferCount == 0)
    }

    @Test func newLinkWaitsWhileIssuedResultIsVisible() async throws {
        let wallet = WalletModel(issuance: PreviewIssuance(delay: .zero), store: MemoryStore())
        wallet.receiveOffer("haip-vci://first")
        let firstFlow = try #require(wallet.incomingOfferFlow)
        await firstFlow.start(using: wallet)
        guard case .ready(let preview) = firstFlow.phase else {
            Issue.record("The first offer did not become ready")
            return
        }
        firstFlow.transactionCode = "123456"
        await firstFlow.receive(preview, using: wallet)
        #expect(firstFlow.isIssued)

        wallet.receiveOffer("haip-vci://second")
        #expect(wallet.incomingOfferFlow === firstFlow)
        #expect(wallet.queuedIncomingOfferCount == 1)
    }

    @Test func linkArrivingDuringSheetDismissalWaitsForOnDismiss() {
        let wallet = WalletModel(issuance: PreviewIssuance(delay: .zero), store: MemoryStore())
        wallet.receiveOffer("haip-vci://first")
        wallet.closeIncomingOffer()
        wallet.receiveOffer("haip-vci://second")

        #expect(wallet.incomingOffer == nil)
        #expect(wallet.queuedIncomingOfferCount == 1)
        wallet.incomingOfferSheetDidDismiss()
        #expect(wallet.incomingOffer?.text == "haip-vci://second")
        #expect(wallet.queuedIncomingOfferCount == 0)
    }
}

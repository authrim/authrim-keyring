import SwiftUI

/// What the user is told for each failure, and what they can do about it.
extension WalletError {
    var title: LocalizedStringKey {
        switch self {
        case .notAnOffer: "This Is Not a Credential Offer"
        case .network, .outcomeUnknown: "Could Not Reach the Issuer"
        case .invalidIssuer: "The Issuer Could Not Be Verified"
        case .transactionCodeRequired: "Enter the Transaction Code"
        case .offerRejected: "The Offer Was Rejected"
        case .invalidCredential: "The Credential Was Not Accepted"
        case .keyUnavailable: "The Secure Key Could Not Be Used"
        case .storage: "The Credential Could Not Be Saved"
        case .offerConsumed: "The Offer Can No Longer Be Used"
        case .notAPresentationRequest: "This Is Not a Request from the Admin Console"
        case .untrustedVerifier: "The Request Was Not Answered"
        case .invalidRequest: "The Request Cannot Be Answered"
        case .noMatchingCredential: "No Admin Credential for This Request"
        case .presentationRefused: "The Admin Console Did Not Accept the Answer"
        }
    }

    var message: LocalizedStringKey {
        switch self {
        case .notAnOffer:
            "The code or link does not contain a credential offer. Ask your administrator for a new one."
        case .network, .outcomeUnknown:
            "Check your connection and try again."
        case .invalidIssuer:
            "The issuer’s information is inconsistent, so Keyring stopped. Nothing was saved. Create a new offer or contact your administrator."
        case .transactionCodeRequired:
            "This offer needs the transaction code shown in the admin console."
        case .offerRejected:
            "The transaction code was wrong or the offer has expired. Create a new offer in the admin console and scan it again."
        case .invalidCredential:
            "The issued credential failed verification, so it was not saved. Create a new offer in the admin console and scan it again."
        case .keyUnavailable:
            "Face ID or the passcode was cancelled, or the Secure Enclave is not available. Try again."
        case .offerConsumed:
            "The one-time code was already used, but the credential could not be completed. Nothing was saved. Create a new code in the admin console and scan it again."
        case .storage:
            "Try again. If it still fails, create a new offer in the admin console."
        case .notAPresentationRequest:
            "The code does not contain a request from the Authrim admin console."
        case .untrustedVerifier:
            "Keyring answers only the Authrim server that issued your admin credential. This request came from somewhere else, so nothing was sent."
        case .invalidRequest:
            "The request is malformed or has expired. Start again in the admin console."
        case .noMatchingCredential:
            "This iPhone holds no admin credential from this server. Issue one in the admin console first (My account → Authrim Keyring)."
        case .presentationRefused:
            "The number may have been wrong, or the request expired. Start again in the admin console."
        }
    }

    /// Technical detail from the wallet, shown small for support.
    var detail: String? {
        switch self {
        case .network(let text), .invalidIssuer(let text), .invalidCredential(let text),
             .keyUnavailable(let text), .storage(let text), .offerConsumed(let text),
             .outcomeUnknown(let text), .untrustedVerifier(let text), .invalidRequest(let text):
            text.isEmpty ? nil : text
        case .presentationRefused(let reason):
            reason
        default:
            nil
        }
    }

    /// Whether trying the same offer again can work. Otherwise a new offer is needed.
    var canRetry: Bool {
        switch self {
        case .network, .outcomeUnknown, .transactionCodeRequired, .keyUnavailable, .storage: true
        case .notAnOffer, .invalidIssuer, .offerRejected, .invalidCredential, .offerConsumed,
             .notAPresentationRequest, .untrustedVerifier, .invalidRequest, .noMatchingCredential,
             .presentationRefused: false
        }
    }
}

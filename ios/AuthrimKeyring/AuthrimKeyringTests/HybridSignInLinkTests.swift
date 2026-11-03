import Foundation
import Testing
@testable import AuthrimKeyring

struct HybridSignInLinkTests {
    @Test func signInCode() {
        #expect(HybridSignInLink.url(from: "FIDO:/0123456789")?.absoluteString == "FIDO:/0123456789")
    }

    @Test func schemeIgnoresCaseAndSpace() {
        #expect(HybridSignInLink.url(from: " fido:/42\n")?.absoluteString == "FIDO:/42")
    }

    @Test func otherCodesAreNotSignInCodes() {
        #expect(HybridSignInLink.url(from: "FIDO:/") == nil)
        #expect(HybridSignInLink.url(from: "FIDO:/12ab") == nil)
        #expect(HybridSignInLink.url(from: "FIDO://example.com") == nil)
        #expect(HybridSignInLink.url(from: "FIDO:/١٢٣") == nil)
        #expect(HybridSignInLink.url(from: "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP") == nil)
    }
}

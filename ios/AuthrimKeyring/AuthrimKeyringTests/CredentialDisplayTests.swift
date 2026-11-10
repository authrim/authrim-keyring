import CryptoKit
import Foundation
import Testing
@testable import AuthrimKeyring

struct CredentialDisplayTests {
    // A one-pixel PNG: tests the actual ImageIO gate rather than only URI parsing.
    private let png = Data(base64Encoded:
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/SAAAAABJRU5ErkJggg==")!

    private func verify(_ sdJwt: String, issuer: TestIssuer, holder: TestSigner) throws -> VerifiedCredential {
        let key = try #require(PublicJWK(from: issuer.issuerJWK))
        return try SDJWTVerifier.verify(
            ParsedSDJWT(sdJwt), issuerKey: key, expectedIssuer: TestIssuer.base,
            expectedVct: TestIssuer.vct, holderKey: holder.publicJWK, now: .now)
    }

    @Test func parsesLocalizedIssuerArtworkAndColors() throws {
        let source = try #require(CredentialDisplayMetadata.issuerSource([
            ["locale": "en", "name": "Diploma", "background_color": "#abc", "text_color": "rgb(255, 255, 255)"],
            ["locale": "ja", "name": "卒業証明", "description": "大学の証明書",
             "logo": ["uri": "data:image/png;base64,\(png.base64EncodedString())", "alt_text": "大学の印"],
             "background_color": "rgb(10%, 20%, 30%)", "text_color": "#fff"],
        ], languages: ["ja-JP", "en-US"]))
        #expect(source.name == "卒業証明")
        #expect(source.description == "大学の証明書")
        #expect(source.backgroundColor == "#1A334D")
        #expect(source.textColor == "#FFFFFF")
        #expect(source.logo?.altText == "大学の印")
        #expect(CredentialDisplayMetadata.color("rgba(255,0,0,0)") == nil)
        #expect(CredentialDisplayMetadata.color("#12345678") == nil)
    }

    @Test func typeSimpleRenderingOverridesIssuerDisplay() async throws {
        let issuer = TestIssuer()
        let holder = TestSigner(tag: "card-test", key: P256.Signing.PrivateKey())
        let sdJwt = try issuer.sdJwt(holder: holder.publicJWK)
        let logoURI = "data:image/png;base64,\(png.base64EncodedString())"
        let metadata: [String: Any] = [
            "vct": TestIssuer.vct,
            "display": [["locale": "en", "name": "Type title", "description": "Type description",
                         "rendering": ["simple": ["background_color": "#234567", "text_color": "#FFFFFF",
                                                  "logo": ["uri": logoURI]]]]],
        ]
        let body = try JSONSerialization.data(withJSONObject: metadata)
        let expectedURL = TestIssuer.vct
        let http = WalletHTTP(testResponse: { request in
            #expect(request.url?.absoluteString == expectedURL)
            return .init(status: 200, data: body, dpopNonce: nil,
                         wwwAuthenticate: nil, clientAttestationChallenge: nil)
        })
        let fallback = CredentialDisplayMetadata.issuerSource(
            [["name": "Issuer title", "background_color": "#ABCDEF"]], languages: ["en"])
        let resolved = try await CredentialDisplayMetadata.resolve(
            issuerSource: fallback, sdJwt: sdJwt, vct: TestIssuer.vct, http: http, languages: ["en"])
        #expect(resolved.name == "Type title")
        #expect(resolved.display?.description == "Type description")
        #expect(resolved.display?.backgroundColor == "#234567")
        #expect(resolved.display?.logoData == png)
    }

    @Test func savesLocalizedClaimLabelsDescriptionsAndDirection() async throws {
        let issuer = TestIssuer()
        let holder = TestSigner(tag: "claim-display", key: P256.Signing.PrivateKey())
        var options = TestIssuer.Options()
        options.extraPayload = ["address": ["city": "東京"]]
        let sdJwt = try issuer.sdJwt(holder: holder.publicJWK, options)
        let verified = try verify(sdJwt, issuer: issuer, holder: holder)
        let issuerClaims: [[String: Any]] = [[
            "path": ["email"], "display": [
                ["locale": "en", "name": "Email"],
                ["locale": "ja", "name": "メール", "description": "連絡先", "dir": "rtl"],
            ],
        ]]
        let sources = CredentialDisplayMetadata.claimSources(issuerClaims, languages: ["ja-JP"])
        let metadata: [String: Any] = [
            "vct": TestIssuer.vct,
            "claims": [["path": ["address", "city"], "display": [
                ["locale": "ja", "label": "都市", "description": "居住地", "dir": "rtl"],
            ]]],
            "display": [["locale": "ja", "name": "資格情報", "dir": "rtl"]],
        ]
        let body = try JSONSerialization.data(withJSONObject: metadata)
        let http = WalletHTTP(testResponse: { _ in
            .init(status: 200, data: body, dpopNonce: nil,
                  wwwAuthenticate: nil, clientAttestationChallenge: nil)
        })
        let resolved = try await CredentialDisplayMetadata.resolve(
            issuerSource: nil, sdJwt: sdJwt, vct: TestIssuer.vct,
            issuerClaimSources: sources, http: http, languages: ["ja-JP"], verified: verified)
        #expect(resolved.display?.nameDirection == .rtl)
        let rows = try #require(resolved.display?.claimDisplays)
        #expect(rows.first(where: { $0.label == "都市" })?.value == "東京")
        #expect(rows.first(where: { $0.label == "都市" })?.description == "居住地")
        #expect(rows.first(where: { $0.label == "メール" })?.value == "admin@example.com")
        #expect(rows.first(where: { $0.label == "メール" })?.direction == .rtl)
        #expect(rows.contains(where: { $0.label == "address" })) // The full raw claim remains visible.
        #expect(CredentialTextDirection.rtl.isolate("abc") == "\u{2067}abc\u{2069}")
        #expect(CredentialTextDirection.auto.isolate("東京") == "\u{2068}東京\u{2069}")
    }

    @Test func selectsSVGForCurrentColorSchemeAndContrast() async throws {
        let issuer = TestIssuer()
        let holder = TestSigner(tag: "variant-display", key: P256.Signing.PrivateKey())
        let sdJwt = try issuer.sdJwt(holder: holder.publicJWK)
        let verified = try verify(sdJwt, issuer: issuer, holder: holder)
        let variants: [(String, String)] = [
            ("light", "normal"), ("dark", "normal"), ("light", "high"), ("dark", "high"),
        ]
        let templates: [[String: Any]] = variants.map { scheme, contrast in
            let svg = Data("<svg xmlns=\"http://www.w3.org/2000/svg\"><text>\(scheme)-\(contrast)</text></svg>".utf8)
            return ["uri": "data:image/svg+xml;base64,\(svg.base64EncodedString())",
                    "properties": ["orientation": "landscape", "color_scheme": scheme,
                                   "contrast": contrast]]
        }
        let body = try JSONSerialization.data(withJSONObject: [
            "vct": TestIssuer.vct,
            "display": [["locale": "en", "name": "Variants", "rendering": [
                "svg_templates": templates,
            ]]],
        ])
        let http = WalletHTTP(testResponse: { _ in
            .init(status: 200, data: body, dpopNonce: nil,
                  wwwAuthenticate: nil, clientAttestationChallenge: nil)
        })
        let result = try await CredentialDisplayMetadata.resolve(
            issuerSource: nil, sdJwt: sdJwt, vct: TestIssuer.vct,
            http: http, languages: ["en"], verified: verified)
        #expect(result.display?.svgVariants?.count == 4)
        let chosen = try #require(result.display?.selectedSVGVariant(colorScheme: "dark", contrast: "high"))
        #expect(String(data: chosen.data, encoding: .utf8)?.contains("dark-high") == true)
        let light = try #require(result.display?.selectedSVGVariant(colorScheme: "light", contrast: "normal"))
        #expect(String(data: light.data, encoding: .utf8)?.contains("light-normal") == true)
        let restored = try JSONDecoder().decode(
            CredentialDisplay.self, from: JSONEncoder().encode(try #require(result.display)))
        #expect(restored.selectedSVGVariant(colorScheme: "dark", contrast: "high")?.data == chosen.data)
    }

    @Test func urnTypeMetadataUsesOnlyIssuerScopedRegistryEntry() async throws {
        let vct = "urn:eu.europa.ec.eudi:learning:credential:1"
        let url = "https://issuer-backend.eudiw.dev/type-metadata/urn%3Aeu.europa.ec.eudi%3Alearning%3Acredential%3A1"
        let body = try JSONSerialization.data(withJSONObject: ["vct": vct, "display": [
            ["locale": "en", "name": "Learning Credential"],
        ]])
        let requests = DisplayRequestLog()
        let http = WalletHTTP(testResponse: { request in
            requests.record(request.url?.absoluteString ?? "")
            return .init(status: 200, data: body, dpopNonce: nil,
                         wwwAuthenticate: nil, clientAttestationChallenge: nil)
        })
        let wrongIssuer = URL(string: "https://other.example.com")!
        #expect(try await SDJWTVCTypeMetadata.load(
            vct: vct, integrity: nil, verified: nil, issuer: wrongIssuer, http: http) == nil)
        #expect(requests.urls.isEmpty)
        let eudiIssuer = URL(string: "https://issuer.eudiw.dev")!
        let result = try await SDJWTVCTypeMetadata.load(
            vct: vct, integrity: nil, verified: nil, issuer: eudiIssuer, http: http)
        #expect(result != nil)
        #expect(requests.urls == [url])
    }

    @Test func urnRegistryDisplayIsUsedAfterCredentialVerification() async throws {
        let vct = "urn:eu.europa.ec.eudi:learning:credential:1"
        let issuerURL = URL(string: "https://issuer.eudiw.dev")!
        let metadataURL = "https://issuer-backend.eudiw.dev/type-metadata/urn%3Aeu.europa.ec.eudi%3Alearning%3Acredential%3A1"
        let issuer = TestIssuer()
        let holder = TestSigner(tag: "urn-display", key: P256.Signing.PrivateKey())
        var options = TestIssuer.Options()
        options.iss = issuerURL.absoluteString
        options.vct = vct
        options.extraPayload = ["name": "Alex"]
        let sdJwt = try issuer.sdJwt(holder: holder.publicJWK, options)
        let key = try #require(PublicJWK(from: issuer.issuerJWK))
        let verified = try SDJWTVerifier.verify(
            ParsedSDJWT(sdJwt), issuerKey: key, expectedIssuer: issuerURL.absoluteString,
            expectedVct: vct, holderKey: holder.publicJWK, now: .now)
        let body = try JSONSerialization.data(withJSONObject: [
            "vct": vct, "claims": [["path": ["name"], "display": [
                ["locale": "en", "label": "Full name"],
            ]]],
            "display": [["locale": "en", "name": "Learning Credential"]],
        ])
        let http = WalletHTTP(testResponse: { request in
            #expect(request.url?.absoluteString == metadataURL)
            return .init(status: 200, data: body, dpopNonce: nil,
                         wwwAuthenticate: nil, clientAttestationChallenge: nil)
        })
        let result = try await CredentialDisplayMetadata.resolve(
            issuerSource: nil, sdJwt: sdJwt, vct: vct,
            issuer: issuerURL, http: http, languages: ["en"], verified: verified)
        #expect(result.name == "Learning Credential")
        #expect(result.display?.claimDisplays?.first(where: { $0.label == "Full name" })?.value == "Alex")
    }

    @Test func invalidIntegrityAndUnprocessedTypeFallBackToIssuer() async throws {
        let issuer = TestIssuer()
        let holder = TestSigner(tag: "card-test", key: P256.Signing.PrivateKey())
        var options = TestIssuer.Options()
        options.extraPayload = ["vct#integrity": "sha256-" + Data(repeating: 0, count: 32).base64EncodedString()]
        let sdJwt = try issuer.sdJwt(holder: holder.publicJWK, options)
        let metadata: [String: Any] = ["vct": TestIssuer.vct,
                                       "display": [["locale": "en", "name": "Untrusted type"]]]
        let body = try JSONSerialization.data(withJSONObject: metadata)
        let http = WalletHTTP(testResponse: { _ in
            .init(status: 200, data: body, dpopNonce: nil,
                  wwwAuthenticate: nil, clientAttestationChallenge: nil)
        })
        let fallback = CredentialDisplayMetadata.issuerSource(
            [["name": "Issuer title", "background_color": "#123456"]], languages: ["en"])
        let resolved = try await CredentialDisplayMetadata.resolve(
            issuerSource: fallback, sdJwt: sdJwt, vct: TestIssuer.vct, http: http, languages: ["en"])
        #expect(resolved.name == nil)
        #expect(resolved.display?.backgroundColor == "#123456")

        let claimMetadata = try JSONSerialization.data(withJSONObject: metadata.merging([
            "claims": [["path": ["email"], "mandatory": true]],
        ]) { _, new in new })
        let httpWithClaims = WalletHTTP(testResponse: { _ in
            .init(status: 200, data: claimMetadata, dpopNonce: nil,
                  wwwAuthenticate: nil, clientAttestationChallenge: nil)
        })
        let plainJWT = try issuer.sdJwt(holder: holder.publicJWK)
        let withClaims = try await CredentialDisplayMetadata.resolve(
            issuerSource: fallback, sdJwt: plainJWT, vct: TestIssuer.vct,
            http: httpWithClaims, languages: ["en"])
        #expect(withClaims.name == nil)
        #expect(withClaims.display?.backgroundColor == "#123456")
    }

    @Test func missingCredentialLogoUsesIssuerLogo() async throws {
        let fallback = CredentialDisplayMetadata.issuerSource(
            [["name": "Credential", "logo": ["uri": "https://images.example.com/missing.png"]]],
            languages: ["en"])
        let issuer = CredentialDisplayMetadata.issuerSource(
            [["name": "Issuer", "logo": ["uri": "data:image/png;base64,\(png.base64EncodedString())",
                                           "alt_text": "Issuer logo"]]], languages: ["en"])
        let missingURL = "https://images.example.com/missing.png"
        let http = WalletHTTP(testResponse: { request in
            #expect(request.url?.absoluteString == missingURL)
            return .init(status: 404, data: Data(), dpopNonce: nil,
                         wwwAuthenticate: nil, clientAttestationChallenge: nil)
        })
        let resolved = try await CredentialDisplayMetadata.resolve(
            issuerSource: fallback, sdJwt: "unused~", vct: "urn:example:credential",
            issuerLogo: issuer?.logo, http: http, languages: ["en"])
        #expect(resolved.display?.logoData == png)
        #expect(resolved.display?.logoAltText == "Issuer logo")
    }

    @Test func acceptsStaticSVGAndRejectsActiveSVG() async throws {
        let safe = Data(##"<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32"><rect width="32" height="32" fill="#123456"/></svg>"##.utf8)
        let withDeclaration = Data(("<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + String(decoding: safe, as: UTF8.self)).utf8)
        let unsafe = Data(#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#.utf8)
        #expect(SVGImageValidator.isSafe(safe))
        #expect(SVGImageValidator.isSafe(withDeclaration))
        #expect(!SVGImageValidator.isSafe(unsafe))
        #expect(!SVGImageValidator.isSafe(Data(#"<svg xmlns="http://www.w3.org/2000/svg"><image href="https://tracking.example/pixel"/></svg>"#.utf8)))
        #expect(!SVGImageValidator.isSafe(Data(#"<svg xmlns="http://www.w3.org/2000/svg"><image src="https://tracking.example/pixel"/></svg>"#.utf8)))

        let source = CredentialDisplayMetadata.issuerSource(
            [["name": "Credential", "logo": ["uri": "data:image/svg+xml;base64,\(safe.base64EncodedString())"]]],
            languages: ["en"])
        let http = WalletHTTP(testResponse: { _ in
            Issue.record("A data URI must not trigger a network request")
            return .init(status: 500, data: Data(), dpopNonce: nil,
                         wwwAuthenticate: nil, clientAttestationChallenge: nil)
        })
        let result = try await CredentialDisplayMetadata.resolve(
            issuerSource: source, sdJwt: "unused~", vct: "urn:example:credential",
            http: http, languages: ["en"])
        #expect(result.display?.logoData == safe)
        #expect(result.display?.logoMediaType == "image/svg+xml")
    }

    @Test func svgTemplateEscapesVerifiedClaimsAndSelectsLandscape() async throws {
        let issuer = TestIssuer()
        let holder = TestSigner(tag: "template-test", key: P256.Signing.PrivateKey())
        var options = TestIssuer.Options()
        options.extraPayload = ["name": "Alice & <Admin> \"A\" '", "address": ["city": "Tokyo"]]
        let sdJwt = try issuer.sdJwt(holder: holder.publicJWK, options)
        let verified = try verify(sdJwt, issuer: issuer, holder: holder)
        let portrait = Data(#"<svg xmlns="http://www.w3.org/2000/svg"><text>portrait</text></svg>"#.utf8)
        let landscape = Data(#"<svg xmlns="http://www.w3.org/2000/svg"><text>{{holder}}</text><text>{{email}}</text><text>{{city}}</text></svg>"#.utf8)
        let metadata: [String: Any] = [
            "vct": TestIssuer.vct,
            "claims": [
                ["path": ["name"], "mandatory": true, "sd": "never", "svg_id": "holder"],
                ["path": ["email"], "mandatory": true, "sd": "always", "svg_id": "email"],
                ["path": ["address", "city"], "svg_id": "city"],
            ],
            "display": [["locale": "en", "name": "Employee card", "rendering": [
                "svg_templates": [
                    ["uri": "data:image/svg+xml;base64,\(portrait.base64EncodedString())",
                     "properties": ["orientation": "portrait"]],
                    ["uri": "data:image/svg+xml;base64,\(landscape.base64EncodedString())",
                     "uri#integrity": "sha256-\(Data(SHA256.hash(data: landscape)).base64EncodedString())",
                     "properties": ["orientation": "landscape"]],
                ],
            ]]],
        ]
        let body = try JSONSerialization.data(withJSONObject: metadata)
        let http = WalletHTTP(testResponse: { request in
            #expect(request.url?.absoluteString == TestIssuer.vct)
            return .init(status: 200, data: body, dpopNonce: nil,
                         wwwAuthenticate: nil, clientAttestationChallenge: nil)
        })
        let result = try await CredentialDisplayMetadata.resolve(
            issuerSource: nil, sdJwt: sdJwt, vct: TestIssuer.vct,
            http: http, languages: ["en"], verified: verified)
        #expect(result.name == "Employee card")
        let face = try #require(result.display?.selectedSVGVariant(colorScheme: "light", contrast: "normal")?.data)
        let text = try #require(String(data: face, encoding: .utf8))
        #expect(text.contains("Alice &amp; &lt;Admin&gt; &quot;A&quot; &apos;"))
        #expect(text.contains("admin@example.com"))
        #expect(text.contains("Tokyo"))
        #expect(!text.contains("portrait"))
        #expect(SVGImageValidator.isSafe(face))
    }

    @Test func inheritedClaimMetadataAndIntegrityAreRequiredForTemplate() async throws {
        let issuer = TestIssuer()
        let holder = TestSigner(tag: "template-inheritance", key: P256.Signing.PrivateKey())
        var options = TestIssuer.Options()
        options.extraPayload = ["name": "Alex"]
        let sdJwt = try issuer.sdJwt(holder: holder.publicJWK, options)
        let verified = try verify(sdJwt, issuer: issuer, holder: holder)
        let baseURL = "https://issuer.example.com/vct/base"
        let base = try JSONSerialization.data(withJSONObject: [
            "vct": baseURL, "claims": [["path": ["name"], "mandatory": true, "svg_id": "holder"]],
        ])
        let face = Data(#"<svg xmlns="http://www.w3.org/2000/svg"><text>{{holder}}</text></svg>"#.utf8)
        func child(_ integrity: String) throws -> Data {
            try JSONSerialization.data(withJSONObject: [
                "vct": TestIssuer.vct, "extends": baseURL, "extends#integrity": integrity,
                "display": [["locale": "en", "name": "Inherited", "rendering": [
                    "svg_templates": [["uri": "data:image/svg+xml;base64,\(face.base64EncodedString())"]],
                ]]],
            ])
        }
        let goodHash = "sha256-\(Data(SHA256.hash(data: base)).base64EncodedString())"
        let goodChild = try child(goodHash)
        let http = WalletHTTP(testResponse: { request in
            .init(status: 200, data: request.url?.absoluteString == baseURL ? base : goodChild,
                  dpopNonce: nil, wwwAuthenticate: nil, clientAttestationChallenge: nil)
        })
        let result = try await CredentialDisplayMetadata.resolve(
            issuerSource: nil, sdJwt: sdJwt, vct: TestIssuer.vct,
            http: http, languages: ["en"], verified: verified)
        #expect(String(data: try #require(result.display?.selectedSVGVariant(colorScheme: "light", contrast: "normal")?.data), encoding: .utf8)?.contains("Alex") == true)

        let badChild = try child("sha256-" + Data(repeating: 0, count: 32).base64EncodedString())
        let badHTTP = WalletHTTP(testResponse: { request in
            .init(status: 200, data: request.url?.absoluteString == baseURL ? base : badChild,
                  dpopNonce: nil, wwwAuthenticate: nil, clientAttestationChallenge: nil)
        })
        let fallback = CredentialDisplayMetadata.issuerSource([["name": "Issuer", "background_color": "#123456"]], languages: ["en"])
        let rejected = try await CredentialDisplayMetadata.resolve(
            issuerSource: fallback, sdJwt: sdJwt, vct: TestIssuer.vct,
            http: badHTTP, languages: ["en"], verified: verified)
        #expect(rejected.name == nil)
        #expect(rejected.display?.svgVariants == nil)
        #expect(rejected.display?.backgroundColor == "#123456")
    }

    @Test func invalidMandatoryOrDisclosureRulesPreventTypeDisplay() async throws {
        let issuer = TestIssuer()
        let holder = TestSigner(tag: "template-policy", key: P256.Signing.PrivateKey())
        var options = TestIssuer.Options()
        options.extraPayload = ["name": "Alex", "profiles": [["id": "one"], [:]]]
        let sdJwt = try issuer.sdJwt(holder: holder.publicJWK, options)
        let verified = try verify(sdJwt, issuer: issuer, holder: holder)
        let invalidClaims: [[[String: Any]]] = [
            [["path": ["name"], "sd": "always"]],
            [["path": ["email"], "sd": "never"]],
            [["path": ["profiles", NSNull(), "id"], "mandatory": true]],
        ]
        let fallback = CredentialDisplayMetadata.issuerSource(
            [["name": "Issuer card", "background_color": "#102030"]], languages: ["en"])
        for claims in invalidClaims {
            let body = try JSONSerialization.data(withJSONObject: [
                "vct": TestIssuer.vct, "claims": claims,
                "display": [["locale": "en", "name": "Invalid type"]],
            ])
            let http = WalletHTTP(testResponse: { _ in
                .init(status: 200, data: body, dpopNonce: nil,
                      wwwAuthenticate: nil, clientAttestationChallenge: nil)
            })
            await #expect(throws: WalletError.self) {
                try await CredentialDisplayMetadata.resolve(
                    issuerSource: fallback, sdJwt: sdJwt, vct: TestIssuer.vct,
                    http: http, languages: ["en"], verified: verified)
            }
        }
    }

    @Test func svgTemplateRejectsUnknownOrUnsafePlaceholders() {
        let head = #"<svg xmlns="http://www.w3.org/2000/svg">"#
        let values = ["name": "Alex & <script>alert(1)</script> \" '" ]
        let valid = Data((head + "<text>{{name}}</text></svg>").utf8)
        let rendered = SVGImageValidator.renderTemplate(valid, values: values)
        #expect(String(data: rendered ?? Data(), encoding: .utf8)?.contains(
            "Alex &amp; &lt;script&gt;alert(1)&lt;/script&gt; &quot; &apos;") == true)
        #expect(SVGImageValidator.renderTemplate(Data((head + "<text>{{missing}}</text></svg>").utf8), values: values) == nil)
        #expect(SVGImageValidator.renderTemplate(Data((head + #"<text id="{{name}}">x</text></svg>"#).utf8), values: values) == nil)
        #expect(SVGImageValidator.renderTemplate(Data((head + "<!-- {{name}} --><text>x</text></svg>").utf8), values: values) == nil)
        #expect(SVGImageValidator.renderTemplate(Data((head + "<style>text{fill:{{name}}}</style></svg>").utf8), values: values) == nil)
        #expect(!SVGImageValidator.isSafe(Data((head + "<![CDATA[<script>x</script>]]></svg>").utf8)))
        #expect(SVGImageValidator.renderTemplate(Data((head + "<text>{{name}}</text></svg>").utf8),
                                                 values: ["name": "bad\u{0001}value"]) == nil)
    }

    @Test func rejectsUnsafeOrOversizedArtworkWithoutNetworkAccess() async throws {
        let requests = DisplayRequestLog()
        let http = WalletHTTP(testResponse: { request in
            requests.record(request.url?.absoluteString ?? "")
            return .init(status: 200, data: Data("<html>not an image</html>".utf8),
                         dpopNonce: nil, wwwAuthenticate: nil, clientAttestationChallenge: nil)
        })
        let source = CredentialDisplayMetadata.issuerSource(
            [["name": "Credential", "logo": ["uri": "https://127.0.0.1/private"],
              "background_image": ["uri": "data:image/png;base64,\(String(repeating: "A", count: 400_000))"]]],
            languages: ["en"])
        let resolved = try await CredentialDisplayMetadata.resolve(
            issuerSource: source, sdJwt: "not-a-jwt~", vct: "urn:example:credential",
            http: http, languages: ["en"])
        #expect(resolved.display?.logoData == nil)
        #expect(resolved.display?.backgroundImageData == nil)
        #expect(requests.urls.isEmpty)
    }

    @Test func oldStoredCredentialStillDecodes() throws {
        let credential = StoredCredential.previewSample
        var object = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(credential)) as? [String: Any])
        object.removeValue(forKey: "credentialDisplay")
        let decoded = try JSONDecoder().decode(StoredCredential.self, from: JSONSerialization.data(withJSONObject: object))
        #expect(decoded.credentialDisplay == nil)
        #expect(decoded.id == credential.id)
    }
}

private nonisolated final class DisplayRequestLog: @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [String] = []

    func record(_ url: String) {
        lock.lock()
        recorded.append(url)
        lock.unlock()
    }

    var urls: [String] {
        lock.lock()
        defer { lock.unlock() }
        return recorded
    }
}

import CryptoKit
import Foundation
import ImageIO

nonisolated struct CredentialDisplayImage: Sendable {
    let data: Data
    let mediaType: String
}

/// A bounded, local snapshot of issuer-provided card artwork. No network request is made when a
/// saved credential is viewed, and an older Keychain item can decode without this optional field.
nonisolated struct CredentialDisplay: Codable, Hashable, Sendable {
    let description: String?
    let backgroundColor: String?
    let textColor: String?
    let logoAltText: String?
    let logoData: Data?
    let logoMediaType: String?
    let backgroundImageData: Data?
    let backgroundImageMediaType: String?
    var faceSVGData: Data? = nil
    var svgVariants: [CredentialSVGVariant]? = nil
    var nameDirection: CredentialTextDirection? = nil
    var descriptionDirection: CredentialTextDirection? = nil
    var claimDisplays: [CredentialDisplayClaim]? = nil
}

nonisolated struct CredentialDisplaySource: Sendable, Equatable {
    nonisolated struct ImageReference: Sendable, Equatable {
        let uri: String
        let integrity: String?
        let altText: String?
    }

    nonisolated struct SVGTemplateReference: Sendable, Equatable {
        let image: ImageReference
        let orientation: String?
        let colorScheme: String?
        let contrast: String?
    }

    let name: String
    let description: String?
    let direction: CredentialTextDirection
    let backgroundColor: String?
    let textColor: String?
    let logo: ImageReference?
    let backgroundImage: ImageReference?
    let svgTemplates: [SVGTemplateReference]
}

/// Resolves issuer display metadata and fully processed SD-JWT VC Type Metadata. Image and SVG
/// template bytes are snapped at issuance, after signature and integrity checks.
nonisolated enum CredentialDisplayMetadata {
    static let logoLimit = 128 * 1024
    static let backgroundLimit = 256 * 1024
    static let svgVariantsLimit = 1024 * 1024

    static func issuerSource(_ display: Any?, languages: [String]) -> CredentialDisplaySource? {
        guard let entry = localizedEntry(display, languages: languages, requiresLocale: false) else { return nil }
        return source(entry, rendering: entry)
    }

    static func typeSource(_ display: Any?, languages: [String]) -> CredentialDisplaySource? {
        guard let entry = localizedEntry(display, languages: languages, requiresLocale: true) else { return nil }
        guard entry["rendering"] == nil || entry["rendering"] is [String: Any] else { return nil }
        let methods = entry["rendering"] as? [String: Any]
        guard methods?["simple"] == nil || methods?["simple"] is [String: Any] else { return nil }
        let rendering = methods?["simple"] as? [String: Any]
        return source(entry, rendering: rendering ?? [:],
                      templates: svgTemplates(methods?["svg_templates"]))
    }

    static func claimSources(_ claims: Any?, languages: [String]) -> [CredentialClaimDisplaySource] {
        guard let entries = claims as? [[String: Any]] else { return [] }
        return entries.prefix(128).compactMap { entry in
            guard let rawPath = entry["path"] as? [Any],
                  let path = SDJWTVCTypeMetadata.path(from: rawPath),
                  let label = localizedEntry(entry["display"], languages: languages,
                                             requiresLocale: false, nameKey: "name")
            else { return nil }
            return claimSource(path: path, entry: label, nameKey: "name")
        }
    }

    static func resolve(
        issuerSource: CredentialDisplaySource?, sdJwt: String, vct: String,
        issuerLogo: CredentialDisplaySource.ImageReference? = nil,
        issuerClaimSources: [CredentialClaimDisplaySource] = [],
        issuer: URL? = nil, registry: TypeMetadataRegistry = .eudiTest,
        http: WalletHTTP, languages: [String], verified: VerifiedCredential? = nil
    ) async throws -> (name: String?, display: CredentialDisplay?) {
        let type = try await typeMetadataSource(
            sdJwt: sdJwt, vct: vct, verified: verified, issuer: issuer, registry: registry,
            http: http, languages: languages)
        let chosen = type?.source ?? issuerSource
        let claims = verified.map {
            displayedClaims($0, issuerSources: issuerClaimSources,
                            typeClaims: type?.claims ?? [], languages: languages)
        } ?? []
        guard chosen != nil || issuerLogo != nil || !claims.isEmpty else { return (nil, nil) }
        async let primaryLogo = image(chosen?.logo, maxBytes: logoLimit, http: http)
        async let primaryBackground = image(chosen?.backgroundImage, maxBytes: backgroundLimit, http: http)
        let resolvedLogo = await primaryLogo
        let resolvedBackground = await primaryBackground
        let credentialLogo = resolvedLogo == nil && type != nil
            ? await image(issuerSource?.logo, maxBytes: logoLimit, http: http) : nil
        let fallbackLogo = resolvedLogo == nil && credentialLogo == nil
            ? await image(issuerLogo, maxBytes: logoLimit, http: http) : nil
        let fallbackBackground = resolvedBackground == nil && type != nil
            ? await image(issuerSource?.backgroundImage, maxBytes: backgroundLimit, http: http) : nil
        var display = CredentialDisplay(
            description: chosen?.description ?? issuerSource?.description,
            backgroundColor: chosen?.backgroundColor ?? issuerSource?.backgroundColor,
            textColor: chosen?.textColor ?? issuerSource?.textColor,
            logoAltText: resolvedLogo != nil ? chosen?.logo?.altText
                : credentialLogo != nil ? issuerSource?.logo?.altText : issuerLogo?.altText,
            logoData: (resolvedLogo ?? credentialLogo ?? fallbackLogo)?.data,
            logoMediaType: (resolvedLogo ?? credentialLogo ?? fallbackLogo)?.mediaType,
            backgroundImageData: (resolvedBackground ?? fallbackBackground)?.data,
            backgroundImageMediaType: (resolvedBackground ?? fallbackBackground)?.mediaType)
        display.nameDirection = chosen?.direction
        display.descriptionDirection = chosen?.direction
        display.claimDisplays = claims.isEmpty ? nil : claims
        if let type, let verified {
            let variants = await renderTemplates(type, verified: verified, http: http)
            display.svgVariants = variants.isEmpty ? nil : variants
        }
        return (type?.source?.name, display)
    }

    private struct TypeDisplay {
        let source: CredentialDisplaySource?
        let claims: [SDJWTVCTypeMetadata.Claim]
    }

    private static func typeMetadataSource(
        sdJwt: String, vct: String, verified: VerifiedCredential?,
        issuer: URL?, registry: TypeMetadataRegistry,
        http: WalletHTTP, languages: [String]
    ) async throws -> TypeDisplay? {
        guard let jwt = sdJwt.split(separator: "~", maxSplits: 1).first,
              let payload = JWS.parse(String(jwt))?.payload else { return nil }
        if let issuer, (payload["iss"] as? String) != issuer.absoluteString { return nil }
        guard payload["vct#integrity"] == nil || payload["vct#integrity"] is String else { return nil }
        let integrity = payload["vct#integrity"] as? String
        let metadata: SDJWTVCTypeMetadata.Processed?
        do {
            metadata = try await SDJWTVCTypeMetadata.load(
                vct: vct, integrity: integrity, verified: verified,
                issuer: issuer, registry: registry, http: http)
        } catch {
            throw WalletError.invalidCredential("The credential violates its type metadata.")
        }
        guard let metadata else { return nil }
        return TypeDisplay(source: typeSource(metadata.display, languages: languages), claims: metadata.claims)
    }

    private static func source(
        _ entry: [String: Any], rendering: [String: Any],
        templates: [CredentialDisplaySource.SVGTemplateReference] = []
    ) -> CredentialDisplaySource? {
        guard let name = (entry["name"] as? String).flatMap(IssuerMetadata.sanitize) else { return nil }
        return CredentialDisplaySource(
            name: name,
            description: (entry["description"] as? String).flatMap { IssuerMetadata.sanitize($0, maxLength: 300) },
            direction: CredentialTextDirection(rawValue: entry["dir"] as? String ?? "auto") ?? .auto,
            backgroundColor: color(rendering["background_color"] as? String),
            textColor: color(rendering["text_color"] as? String),
            logo: imageReference(rendering["logo"]),
            backgroundImage: imageReference(rendering["background_image"]),
            svgTemplates: templates)
    }

    private static func svgTemplates(_ value: Any?) -> [CredentialDisplaySource.SVGTemplateReference] {
        guard let value else { return [] }
        guard let entries = value as? [[String: Any]], !entries.isEmpty, entries.count <= 8 else { return [] }
        var result: [CredentialDisplaySource.SVGTemplateReference] = []
        for entry in entries {
            guard let reference = imageReference(entry) else { return [] }
            let properties = entry["properties"] as? [String: Any]
            guard entries.count == 1 || properties?.isEmpty == false,
                  entry["properties"] == nil || properties != nil else { return [] }
            func property(_ name: String, allowed: Set<String>) -> String? {
                guard let raw = properties?[name] else { return nil }
                guard let text = raw as? String, allowed.contains(text) else { return "invalid" }
                return text
            }
            let orientation = property("orientation", allowed: ["portrait", "landscape"])
            let colorScheme = property("color_scheme", allowed: ["light", "dark"])
            let contrast = property("contrast", allowed: ["normal", "high"])
            guard orientation != "invalid", colorScheme != "invalid", contrast != "invalid" else { return [] }
            guard entries.count == 1 || orientation != nil || colorScheme != nil || contrast != nil else { return [] }
            result.append(.init(image: reference, orientation: orientation,
                                colorScheme: colorScheme, contrast: contrast))
        }
        return result
    }

    private static func displayedClaims(
        _ credential: VerifiedCredential, issuerSources: [CredentialClaimDisplaySource],
        typeClaims: [SDJWTVCTypeMetadata.Claim], languages: [String]
    ) -> [CredentialDisplayClaim] {
        guard let payload = (try? JSONSerialization.jsonObject(with: credential.resolvedPayload)) as? [String: Any]
        else { return [] }
        let typeSources: [CredentialClaimDisplaySource] = typeClaims.compactMap { claim in
            guard let entry = localizedEntry(claim.display, languages: languages,
                                             requiresLocale: true, nameKey: "label")
            else { return nil }
            return claimSource(path: claim.path, entry: entry, nameKey: "label")
        }
        var rows: [CredentialDisplayClaim] = []
        var usedPaths = Set<[SDJWTVCTypeMetadata.PathPart]>()
        var namedTopLevel = Set<String>()
        for source in typeSources + issuerSources {
            guard rows.count < SDJWTVerifier.maxDisplayedClaims,
                  case .some(.name(let root)) = source.path.first,
                  credential.claims[root] != nil else { continue }
            guard !usedPaths.contains(source.path) else { continue }
            let probe = SDJWTVCTypeMetadata.Claim(
                path: source.path, mandatory: nil, sd: nil, svgID: nil, display: nil)
            guard let selected = SDJWTVCTypeMetadata.values(for: probe, in: payload) else { continue }
            usedPaths.insert(source.path)
            if source.path.count == 1 { namedTopLevel.insert(root) }
            for (index, (value, path)) in selected.enumerated() {
                guard rows.count < SDJWTVerifier.maxDisplayedClaims else { break }
                let label = selected.count > 1 ? "\(source.label) \(index + 1)" : source.label
                rows.append(CredentialDisplayClaim(
                    id: pathID(path), label: label, value: SDJWTVerifier.displayText(value),
                    description: source.description, direction: source.direction))
            }
        }
        for (name, value) in credential.claims.sorted(by: { $0.key < $1.key })
            where rows.count < SDJWTVerifier.maxDisplayedClaims && !namedTopLevel.contains(name) {
            rows.append(CredentialDisplayClaim(
                id: "raw:" + Base64URL.encode(Data(name.utf8)), label: name, value: value,
                description: nil, direction: .auto))
        }
        return rows
    }

    private static func pathID(_ path: [SDJWTClaimPathComponent]) -> String {
        path.map { part in
            switch part {
            case .name(let name): "n" + Base64URL.encode(Data(name.utf8))
            case .index(let index): "i\(index)"
            }
        }.joined(separator: "/")
    }

    private static func claimSource(
        path: [SDJWTVCTypeMetadata.PathPart], entry: [String: Any], nameKey: String
    ) -> CredentialClaimDisplaySource? {
        guard let label = (entry[nameKey] as? String).flatMap(IssuerMetadata.sanitize) else { return nil }
        return CredentialClaimDisplaySource(
            path: path, label: label,
            description: (entry["description"] as? String).flatMap {
                IssuerMetadata.sanitize($0, maxLength: 300)
            },
            direction: CredentialTextDirection(rawValue: entry["dir"] as? String ?? "auto") ?? .auto)
    }

    private static func renderTemplates(
        _ type: TypeDisplay, verified: VerifiedCredential, http: WalletHTTP
    ) async -> [CredentialSVGVariant] {
        guard let payload = (try? JSONSerialization.jsonObject(with: verified.resolvedPayload)) as? [String: Any],
              let references = type.source?.svgTemplates, !references.isEmpty else { return [] }
        var values: [String: String] = [:]
        for claim in type.claims {
            guard let id = claim.svgID else { continue }
            guard id.range(of: #"^[A-Za-z_][A-Za-z0-9_]*$"#, options: .regularExpression) != nil,
                  !claim.path.contains(.all), values[id] == nil,
                  let selected = SDJWTVCTypeMetadata.values(for: claim, in: payload),
                  selected.count <= 1 else { return [] }
            if let selectedValue = selected.first {
                let text = SDJWTVerifier.display(selectedValue.0)
                guard text.count <= SDJWTVerifier.maxClaimValueLength else { return [] }
                values[id] = text
            } else {
                values[id] = ""
            }
        }
        let substitutions = values
        let rendered = await withTaskGroup(of: (Int, CredentialSVGVariant?).self) { group in
            for (index, reference) in references.enumerated() {
                group.addTask {
                    guard let asset = await image(reference.image, maxBytes: backgroundLimit, http: http),
                          asset.mediaType == "image/svg+xml",
                          let data = SVGImageValidator.renderTemplate(asset.data, values: substitutions)
                    else { return (index, nil) }
                    return (index, CredentialSVGVariant(
                        data: data, orientation: reference.orientation,
                        colorScheme: reference.colorScheme, contrast: reference.contrast))
                }
            }
            var collected: [(Int, CredentialSVGVariant)] = []
            for await (index, variant) in group {
                if let variant { collected.append((index, variant)) }
            }
            return collected.sorted { $0.0 < $1.0 }.map(\.1)
        }
        var selected: [CredentialSVGVariant] = []
        var total = 0
        for scheme in ["light", "dark"] {
            for contrast in ["normal", "high"] {
                guard let best = rendered.enumerated().max(by: { a, b in
                    let left = a.element.score(colorScheme: scheme, contrast: contrast)
                    let right = b.element.score(colorScheme: scheme, contrast: contrast)
                    return left == right ? a.offset > b.offset : left < right
                })?.element, !selected.contains(best) else { continue }
                guard total + best.data.count <= svgVariantsLimit else { continue }
                total += best.data.count
                selected.append(best)
            }
        }
        return selected
    }

    private static func localizedEntry(
        _ value: Any?, languages: [String], requiresLocale: Bool, nameKey: String = "name"
    ) -> [String: Any]? {
        guard let entries = value as? [[String: Any]] else { return nil }
        let named = entries.filter {
            ($0[nameKey] as? String).flatMap(IssuerMetadata.sanitize) != nil &&
                (!requiresLocale || ($0["locale"] as? String)?.isEmpty == false)
        }
        func language(_ tag: String) -> String {
            tag.lowercased().split(whereSeparator: { $0 == "-" || $0 == "_" }).first.map(String.init) ?? ""
        }
        for preferred in languages {
            let tag = preferred.lowercased().replacingOccurrences(of: "_", with: "-")
            if let match = named.first(where: { ($0["locale"] as? String)?.lowercased() == tag }) { return match }
            if let match = named.first(where: { ($0["locale"] as? String).map(language) == language(tag) }) {
                return match
            }
        }
        if let english = named.first(where: { ($0["locale"] as? String).map(language) == "en" }) { return english }
        return named.first(where: { $0["locale"] == nil }) ?? named.first
    }

    /// Only opaque RGB values are useful on a card. CSS 3 numerical #RGB, #RRGGBB and rgb()
    /// values are normalized so the UI never has to interpret arbitrary CSS from an issuer.
    static func color(_ raw: String?) -> String? {
        guard let raw else { return nil }
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.count == 4, value.first == "#",
           value.dropFirst().allSatisfy({ $0.isHexDigit }) {
            return "#" + value.dropFirst().map { String(repeating: String($0).uppercased(), count: 2) }.joined()
        }
        if value.count == 7, value.first == "#",
           value.dropFirst().allSatisfy({ $0.isHexDigit }) { return value.uppercased() }
        guard value.lowercased().hasPrefix("rgb("), value.hasSuffix(")") else { return nil }
        let inner = value.dropFirst(4).dropLast()
        let components = inner.split(separator: ",", omittingEmptySubsequences: false)
        guard components.count == 3 else { return nil }
        var bytes: [Int] = []
        for component in components {
            let text = component.trimmingCharacters(in: .whitespaces)
            if text.hasSuffix("%"), let percentage = Double(text.dropLast()),
               percentage.isFinite, (0...100).contains(percentage) {
                bytes.append(Int((percentage * 255 / 100).rounded()))
            } else if text.allSatisfy({ $0.isNumber }), let byte = Int(text), (0...255).contains(byte) {
                bytes.append(byte)
            } else { return nil }
        }
        return String(format: "#%02X%02X%02X", bytes[0], bytes[1], bytes[2])
    }

    private static func imageReference(_ value: Any?) -> CredentialDisplaySource.ImageReference? {
        guard let object = value as? [String: Any], let uri = object["uri"] as? String,
              !uri.isEmpty, uri.utf8.count <= 400_000 else { return nil }
        guard object["uri#integrity"] == nil || object["uri#integrity"] is String else { return nil }
        let integrity = object["uri#integrity"] as? String
        return .init(uri: uri, integrity: integrity,
                     altText: (object["alt_text"] as? String).flatMap(IssuerMetadata.sanitize))
    }

    private static func image(
        _ reference: CredentialDisplaySource.ImageReference?, maxBytes: Int, http: WalletHTTP
    ) async -> CredentialDisplayImage? {
        guard let reference else { return nil }
        let data: Data
        var declaredType: String?
        if reference.uri.lowercased().hasPrefix("data:") {
            guard let comma = reference.uri.firstIndex(of: ",") else { return nil }
            let header = reference.uri[..<comma].lowercased()
            let components = header.dropFirst(5).split(separator: ";")
            guard let mediaType = components.first.map(String.init),
                  ["image/png", "image/jpeg", "image/svg+xml"].contains(mediaType),
                  components.dropFirst().allSatisfy({ $0 == "base64" || $0 == "charset=utf-8" }) else { return nil }
            declaredType = mediaType
            let encoded = reference.uri[reference.uri.index(after: comma)...]
            let isBase64 = components.contains("base64")
            guard encoded.utf8.count <= (isBase64 ? (maxBytes * 4 / 3) + 8 : maxBytes * 3),
                  let decoded = isBase64 ? Data(base64Encoded: String(encoded)) : percentDecodedData(encoded),
                  decoded.count <= maxBytes else { return nil }
            data = decoded
        } else {
            guard reference.uri.utf8.count <= 2048,
                  let url = URL(string: reference.uri), url.fragment == nil,
                  (try? WalletHTTP.requireHTTPS(url, "The credential artwork")) != nil else { return nil }
            do {
                let response = try await http.send(
                    url, headers: ["Accept": "image/png, image/jpeg, image/svg+xml"], maxBytes: maxBytes)
                guard response.status == 200, response.data.count <= maxBytes else { return nil }
                data = response.data
            } catch { return nil }
        }
        guard verifyIntegrity(data, expected: reference.integrity) else { return nil }
        if SVGImageValidator.isSafe(data) {
            guard declaredType == nil || declaredType == "image/svg+xml" else { return nil }
            return .init(data: data, mediaType: "image/svg+xml")
        }
        guard let source = CGImageSourceCreateWithData(data as CFData, nil),
              CGImageSourceGetCount(source) == 1,
              let type = CGImageSourceGetType(source) as String?,
              type == "public.png" || type == "public.jpeg",
              let properties = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [String: Any],
              let width = properties[kCGImagePropertyPixelWidth as String] as? Int,
              let height = properties[kCGImagePropertyPixelHeight as String] as? Int,
              width > 0, height > 0, width <= 4096, height <= 4096,
              width * height <= 4_000_000 else { return nil }
        let mediaType = type == "public.png" ? "image/png" : "image/jpeg"
        guard declaredType == nil || declaredType == mediaType else { return nil }
        return .init(data: data, mediaType: mediaType)
    }

    private static func percentDecodedData(_ encoded: Substring) -> Data? {
        let bytes = Array(encoded.utf8)
        var result = Data()
        result.reserveCapacity(bytes.count)
        var index = 0
        while index < bytes.count {
            if bytes[index] == 0x25 {
                guard index + 2 < bytes.count,
                      let value = UInt8(String(decoding: bytes[(index + 1)...(index + 2)], as: UTF8.self), radix: 16)
                else { return nil }
                result.append(value)
                index += 3
            } else {
                result.append(bytes[index])
                index += 1
            }
        }
        return result
    }

    /// SRI-style integrity strings on type metadata and artwork. Prefer the strongest supported
    /// hash and accept any matching expression of that strength, as required by SD-JWT VC 6.
    static func verifyIntegrity(_ data: Data, expected: String?) -> Bool {
        guard let expected else { return true }
        let expressions = expected.split(whereSeparator: \.isWhitespace).compactMap { part -> (strength: Int, digest: Data)? in
            let fields = part.split(separator: "-", maxSplits: 1)
            guard fields.count == 2, let digest = Data(base64Encoded: String(fields[1])) else { return nil }
            let strength: Int
            switch fields[0] {
            case "sha256": strength = 256
            case "sha384": strength = 384
            case "sha512": strength = 512
            default: return nil
            }
            return (strength, digest)
        }
        guard let strongest = expressions.map(\.strength).max() else { return false }
        let actual: Data
        switch strongest {
        case 512: actual = Data(SHA512.hash(data: data))
        case 384: actual = Data(SHA384.hash(data: data))
        default: actual = Data(SHA256.hash(data: data))
        }
        return expressions.contains { $0.strength == strongest && $0.digest == actual }
    }
}

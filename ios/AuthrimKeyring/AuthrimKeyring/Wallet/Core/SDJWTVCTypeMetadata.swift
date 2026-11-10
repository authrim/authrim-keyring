import Foundation

/// The part of SD-JWT VC Type Metadata used for card rendering. Type Metadata is optional in this
/// wallet, but a document is never used for display until its whole HTTPS extension chain and all
/// claim-metadata rules have been processed against the verified credential.
nonisolated enum SDJWTVCTypeMetadata {
    enum PathPart: Hashable, Sendable {
        case name(String)
        case index(Int)
        case all
    }

    struct Claim {
        let path: [PathPart]
        let mandatory: Bool?
        let sd: String?
        let svgID: String?
        let display: Any?
    }

    struct Processed {
        let display: Any?
        let claims: [Claim]
    }

    private static let maxDepth = 5
    private static let maxClaims = 128

    static func load(
        vct: String, integrity: String?, verified: VerifiedCredential?,
        issuer: URL? = nil, registry: TypeMetadataRegistry = .eudiTest, http: WalletHTTP
    ) async throws -> Processed? {
        guard let processed = try await loadDocument(
            vct: vct, integrity: integrity, issuer: issuer, registry: registry,
            http: http, visited: [], depth: 0) else { return nil }
        // The type metadata can only be used after claim validation. The issuance verifier has
        // all disclosures that were supplied; an undisclosed value makes this validation uncertain.
        guard !processed.claims.isEmpty else { return processed }
        guard let verified, !verified.hasUndisclosedClaims else { return nil }
        guard validate(processed.claims, credential: verified) else {
            throw WalletError.invalidCredential("The credential violates its type's claim rules.")
        }
        return processed
    }

    private static func loadDocument(
        vct: String, integrity: String?, issuer: URL?, registry: TypeMetadataRegistry, http: WalletHTTP,
        visited: Set<String>, depth: Int
    ) async throws -> Processed? {
        guard depth < maxDepth, !visited.contains(vct),
              let url = (URL(string: vct).flatMap { $0.scheme?.lowercased() == "https" ? $0 : nil }
                         ?? registry.url(for: vct, issuer: issuer)), url.fragment == nil,
              (try? WalletHTTP.requireHTTPS(url, "The credential type")) != nil else { return nil }
        let response: WalletHTTPResponse
        do {
            response = try await http.send(url, maxBytes: WalletHTTP.jsonLimit)
        } catch { return nil }
        guard response.status == 200, response.data.count <= WalletHTTP.jsonLimit,
              CredentialDisplayMetadata.verifyIntegrity(response.data, expected: integrity),
              let object = (try? JSONSerialization.jsonObject(with: response.data)) as? [String: Any],
              (object["vct"] as? String) == vct else { return nil }
        guard object["extends#integrity"] == nil || object["extends#integrity"] is String else { return nil }
        guard object["claims"] == nil || object["claims"] is [Any] else { return nil }
        let ownClaims = try parseClaims(object["claims"] as? [Any] ?? [])
        let parent: Processed?
        if let base = object["extends"] as? String {
            parent = try await loadDocument(
                vct: base, integrity: object["extends#integrity"] as? String,
                issuer: issuer, registry: registry, http: http,
                visited: visited.union([vct]), depth: depth + 1)
            guard parent != nil else { return nil }
        } else {
            guard object["extends"] == nil, object["extends#integrity"] == nil else { return nil }
            parent = nil
        }
        let claims = try merge(parent?.claims ?? [], with: ownClaims)
        return Processed(display: object["display"] ?? parent?.display, claims: claims)
    }

    private static func parseClaims(_ entries: [Any]) throws -> [Claim] {
        guard entries.count <= maxClaims else { throw TypeError.invalid }
        var result: [Claim] = []
        var paths = Set<[PathPart]>()
        for entry in entries {
            guard let object = entry as? [String: Any],
                  let rawPath = object["path"] as? [Any], !rawPath.isEmpty,
                  rawPath.count <= 64 else { throw TypeError.invalid }
            guard let path = path(from: rawPath) else { throw TypeError.invalid }
            guard paths.insert(path).inserted else { throw TypeError.invalid }
            let mandatory: Bool?
            if let value = object["mandatory"] {
                guard let number = value as? NSNumber,
                      CFGetTypeID(number) == CFBooleanGetTypeID() else { throw TypeError.invalid }
                mandatory = number.boolValue
            } else { mandatory = nil }
            let sd: String?
            if let value = object["sd"] {
                guard let text = value as? String, ["always", "allowed", "never"].contains(text)
                else { throw TypeError.invalid }
                sd = text
            } else { sd = nil }
            let svgID = object["svg_id"] as? String
            result.append(Claim(path: path, mandatory: mandatory, sd: sd,
                                svgID: svgID, display: object["display"]))
        }
        return result
    }

    private static func merge(_ parent: [Claim], with child: [Claim]) throws -> [Claim] {
        var result = parent
        for own in child {
            if let index = result.firstIndex(where: { $0.path == own.path }) {
                let base = result[index]
                if base.mandatory == true, own.mandatory == false { throw TypeError.invalid }
                if let baseSD = base.sd, baseSD != "allowed", let ownSD = own.sd, ownSD != baseSD {
                    throw TypeError.invalid
                }
                result[index] = Claim(
                    path: own.path, mandatory: own.mandatory ?? base.mandatory,
                    sd: own.sd ?? base.sd, svgID: own.svgID ?? base.svgID,
                    display: own.display ?? base.display)
            } else { result.append(own) }
        }
        guard result.count <= maxClaims else { throw TypeError.invalid }
        return result
    }

    static func path(from rawPath: [Any]) -> [PathPart]? {
        guard !rawPath.isEmpty, rawPath.count <= 64 else { return nil }
        var path: [PathPart] = []
        for part in rawPath {
            if part is NSNull { path.append(.all) }
            else if let name = part as? String { path.append(.name(name)) }
            else if let number = part as? NSNumber,
                    CFGetTypeID(number) != CFBooleanGetTypeID(),
                    number.doubleValue.isFinite,
                    number.doubleValue >= 0,
                    number.doubleValue <= Double(Int.max),
                    number.doubleValue.rounded(.towardZero) == number.doubleValue {
                path.append(.index(number.intValue))
            } else { return nil }
        }
        return path
    }

    /// Returns a single value for a template placeholder. The same evaluator also checks
    /// mandatory and selective-disclosure policy for every claim-metadata entry.
    static func values(for claim: Claim, in payload: [String: Any]) -> [(Any, [SDJWTClaimPathComponent])]? {
        var selection: [(Any, [SDJWTClaimPathComponent])] = [(payload, [])]
        for part in claim.path {
            var next: [(Any, [SDJWTClaimPathComponent])] = []
            for (value, path) in selection {
                switch part {
                case .name(let key):
                    guard let object = value as? [String: Any] else { return nil }
                    if let child = object[key] { next.append((child, path + [.name(key)])) }
                    else if claim.mandatory == true { return nil }
                case .index(let index):
                    guard let array = value as? [Any] else { return nil }
                    if index < array.count { next.append((array[index], path + [.index(index)])) }
                    else if claim.mandatory == true { return nil }
                case .all:
                    guard let array = value as? [Any] else { return nil }
                    next += array.enumerated().map { ($0.element, path + [.index($0.offset)]) }
                }
            }
            selection = next
        }
        return selection
    }

    private static func validate(_ claims: [Claim], credential: VerifiedCredential) -> Bool {
        guard let payload = (try? JSONSerialization.jsonObject(with: credential.resolvedPayload)) as? [String: Any]
        else { return false }
        for claim in claims {
            guard let selected = values(for: claim, in: payload) else { return false }
            for (_, path) in selected {
                let disclosed = credential.selectivelyDisclosedPaths.contains(path)
                if claim.sd == "always" && !disclosed { return false }
                if claim.sd == "never" && disclosed { return false }
            }
        }
        return true
    }

    private enum TypeError: Error { case invalid }
}

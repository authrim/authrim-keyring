import Foundation

/// Explicit issuer-scoped URN mappings. A URN is never interpolated into an arbitrary network URL.
nonisolated struct TypeMetadataRegistry: Sendable {
    nonisolated struct Entry: Sendable {
        let issuer: String
        let vct: String
        let url: URL
    }

    let entries: [Entry]

    static let eudiTest = TypeMetadataRegistry(entries: [
        Entry(
            issuer: "https://issuer.eudiw.dev",
            vct: "urn:eu.europa.ec.eudi:learning:credential:1",
            url: URL(string: "https://issuer-backend.eudiw.dev/type-metadata/urn%3Aeu.europa.ec.eudi%3Alearning%3Acredential%3A1")!),
    ])

    func url(for vct: String, issuer: URL?) -> URL? {
        guard let issuer else { return nil }
        return entries.first { $0.issuer == issuer.absoluteString && $0.vct == vct }?.url
    }
}

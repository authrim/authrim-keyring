import Foundation

/// A bounded, validated local snapshot of one SVG template variant.
nonisolated struct CredentialSVGVariant: Codable, Hashable, Sendable {
    let data: Data
    let orientation: String?
    let colorScheme: String?
    let contrast: String?

    func score(colorScheme preferredColor: String, contrast preferredContrast: String) -> Int {
        (orientation == "landscape" ? 8 : orientation == nil ? 4 : 0) +
            (colorScheme == preferredColor ? 4 : colorScheme == nil ? 2 : 0) +
            (contrast == preferredContrast ? 2 : contrast == nil ? 1 : 0)
    }
}

extension CredentialDisplay {
    nonisolated func selectedSVGVariant(colorScheme: String, contrast: String) -> CredentialSVGVariant? {
        if let variants = svgVariants, !variants.isEmpty {
            return variants.enumerated().max { left, right in
                let a = left.element.score(colorScheme: colorScheme, contrast: contrast)
                let b = right.element.score(colorScheme: colorScheme, contrast: contrast)
                return a == b ? left.offset > right.offset : a < b
            }?.element
        }
        return faceSVGData.map {
            CredentialSVGVariant(data: $0, orientation: "landscape", colorScheme: nil, contrast: nil)
        }
    }
}
